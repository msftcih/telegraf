//go:generate ../../../tools/readme_config_includer/generator
package event_hubs

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/internal"
	"github.com/influxdata/telegraf/plugins/outputs"
)

//go:embed sample.conf
var sampleConfig string

type EventHubs struct {
	ConnectionString string          `toml:"connection_string"`
	PartitionKey     string          `toml:"partition_key"`
	MaxMessageSize   config.Size     `toml:"max_message_size"`
	Timeout          config.Duration `toml:"timeout"`
	Log              telegraf.Logger `toml:"-"`

	// Managed Identity Configuration
	UseManagedIdentity bool   `toml:"use_managed_identity"`
	ManagedIdentityID  string `toml:"managed_identity_id"`
	EventHubNamespace  string `toml:"eventhub_namespace"`
	EventHubName       string `toml:"eventhub_name"`

	client     *azeventhubs.ProducerClient
	options    azeventhubs.EventDataBatchOptions
	serializer telegraf.Serializer
}

func (*EventHubs) SampleConfig() string {
	return sampleConfig
}

func (e *EventHubs) Init() error {
	if e.MaxMessageSize > 0 {
		e.options.MaxBytes = uint64(e.MaxMessageSize)
	}

	return nil
}

// createManagedIdentityCredential creates a managed identity credential
// This function intelligently chooses between Azure Workload Identity (for AKS) and Managed Identity (for VMs)
func (e *EventHubs) createManagedIdentityCredential() (azcore.TokenCredential, error) {
	// Check if we're in an Azure Workload Identity environment
	if e.isWorkloadIdentityEnvironment() {
		e.Log.Info("Detected Azure Workload Identity environment, attempting workload identity authentication")
		return e.createWorkloadIdentityCredential()
	}

	// Fall back to traditional Managed Identity
	e.Log.Info("Using traditional Azure Managed Identity authentication")
	return e.createTraditionalManagedIdentityCredential()
}

// isWorkloadIdentityEnvironment checks if we're running in an Azure Workload Identity environment
func (e *EventHubs) isWorkloadIdentityEnvironment() bool {
	// Azure Workload Identity sets these environment variables
	return os.Getenv("AZURE_CLIENT_ID") != "" &&
		os.Getenv("AZURE_TENANT_ID") != "" &&
		os.Getenv("AZURE_FEDERATED_TOKEN_FILE") != ""
}

// createWorkloadIdentityCredential creates a workload identity credential
func (e *EventHubs) createWorkloadIdentityCredential() (azcore.TokenCredential, error) {
	var credential azcore.TokenCredential
	var err error

	// Use the client ID from configuration or environment
	clientID := e.ManagedIdentityID
	if clientID == "" {
		clientID = os.Getenv("AZURE_CLIENT_ID")
	}

	if clientID != "" {
		// Create workload identity credential with explicit client ID
		options := &azidentity.WorkloadIdentityCredentialOptions{
			ClientID:      clientID,
			TenantID:      os.Getenv("AZURE_TENANT_ID"),
			TokenFilePath: os.Getenv("AZURE_FEDERATED_TOKEN_FILE"),
		}
		credential, err = azidentity.NewWorkloadIdentityCredential(options)
		if err != nil {
			return nil, fmt.Errorf("failed to create workload identity credential with client ID %s: %w", clientID, err)
		}
		e.Log.Infof("Created Azure Workload Identity credential with client ID: %s", clientID)
	} else {
		// Use default workload identity credential
		credential, err = azidentity.NewWorkloadIdentityCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create default workload identity credential: %w", err)
		}
		e.Log.Info("Created Azure Workload Identity credential with default settings")
	}

	return credential, nil
}

// createTraditionalManagedIdentityCredential creates a traditional managed identity credential
func (e *EventHubs) createTraditionalManagedIdentityCredential() (azcore.TokenCredential, error) {
	var options *azidentity.ManagedIdentityCredentialOptions

	clientID := e.ManagedIdentityID
	// If no explicit client ID is configured, check environment variable
	if clientID == "" {
		if envClientID := os.Getenv("AZURE_CLIENT_ID"); envClientID != "" {
			clientID = envClientID
			e.Log.Infof("Using client ID from AZURE_CLIENT_ID environment variable: %s", clientID)
		}
	}

	if clientID != "" {
		options = &azidentity.ManagedIdentityCredentialOptions{
			ID: azidentity.ClientID(clientID),
		}
		e.Log.Infof("Creating User-Assigned Managed Identity credential with client ID: %s", clientID)
	} else {
		e.Log.Info("Creating System-Assigned Managed Identity credential")
	}

	cred, err := azidentity.NewManagedIdentityCredential(options)
	if err != nil {
		credType := "system-assigned"
		if clientID != "" {
			credType = fmt.Sprintf("user-assigned (ClientID: %s)", clientID)
		}
		return nil, fmt.Errorf("failed to create %s managed identity credential: %w", credType, err)
	}

	return cred, nil
}

// createDefaultAzureCredential creates a default Azure credential that tries multiple authentication methods
func (e *EventHubs) createDefaultAzureCredential() (azcore.TokenCredential, error) {
	e.Log.Info("Creating DefaultAzureCredential with default settings")

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create DefaultAzureCredential: %w", err)
	}

	return cred, nil
}

func (e *EventHubs) Connect() error {
	cfg := &azeventhubs.ProducerClientOptions{
		ApplicationID: internal.FormatFullVersion(),
		RetryOptions:  azeventhubs.RetryOptions{MaxRetries: -1},
	}

	var client *azeventhubs.ProducerClient
	var err error

	if e.UseManagedIdentity {
		// Use Managed Identity authentication
		if e.EventHubNamespace == "" || e.EventHubName == "" {
			return fmt.Errorf("eventhub_namespace and eventhub_name are required when using managed identity")
		}

		e.Log.Info("Using managed identity authentication for Event Hub")

		// Create managed identity credential
		credential, err := e.createManagedIdentityCredential()
		if err != nil {
			// Fall back to DefaultAzureCredential if managed identity fails
			e.Log.Warnf("Failed to create managed identity credential, falling back to DefaultAzureCredential: %v", err)
			credential, err = e.createDefaultAzureCredential()
			if err != nil {
				return fmt.Errorf("failed to create Azure credential: %w", err)
			}
		}

		// Create Event Hub client with managed identity
		fullyQualifiedNamespace := e.EventHubNamespace
		if !containsScheme(fullyQualifiedNamespace) {
			fullyQualifiedNamespace = fmt.Sprintf("%s.servicebus.windows.net", fullyQualifiedNamespace)
		}

		client, err = azeventhubs.NewProducerClient(fullyQualifiedNamespace, e.EventHubName, credential, cfg)
		if err != nil {
			return fmt.Errorf("failed to create Event Hub client with managed identity: %w", err)
		}

		e.Log.Infof("Successfully connected to Event Hub %s/%s using managed identity", fullyQualifiedNamespace, e.EventHubName)
	} else if e.ConnectionString != "" {
		// Use connection string authentication
		e.Log.Info("Using connection string authentication for Event Hub")
		client, err = azeventhubs.NewProducerClientFromConnectionString(e.ConnectionString, "", cfg)
		if err != nil {
			return fmt.Errorf("failed to create client from connection string: %w", err)
		}
	} else {
		return fmt.Errorf("either connection_string or managed identity configuration (use_managed_identity=true, eventhub_namespace, eventhub_name) must be provided")
	}

	e.client = client
	return nil
}

// containsScheme checks if the namespace already contains a scheme (http:// or https://)
func containsScheme(namespace string) bool {
	return (len(namespace) >= 7 && namespace[:7] == "http://") ||
		(len(namespace) >= 8 && namespace[:8] == "https://")
}

func (e *EventHubs) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(e.Timeout))
	defer cancel()

	return e.client.Close(ctx)
}

func (e *EventHubs) SetSerializer(serializer telegraf.Serializer) {
	e.serializer = serializer
}

func (e *EventHubs) Write(metrics []telegraf.Metric) error {
	ctx := context.Background()

	batchOptions := e.options
	batches := make(map[string]*azeventhubs.EventDataBatch)
	for i := 0; i < len(metrics); i++ {
		m := metrics[i]

		// Prepare the payload
		payload, err := e.serializer.Serialize(m)
		if err != nil {
			e.Log.Errorf("Could not serialize metric: %v", err)
			e.Log.Tracef("metric: %+v", m)
			continue
		}

		// Get the batcher for the chosen partition
		partition := "<default>"
		batchOptions.PartitionKey = nil
		if e.PartitionKey != "" {
			if key, ok := m.GetTag(e.PartitionKey); ok {
				partition = key
				batchOptions.PartitionKey = &partition
			} else if key, ok := m.GetField(e.PartitionKey); ok {
				if k, ok := key.(string); ok {
					partition = k
					batchOptions.PartitionKey = &partition
				}
			}
		}
		if _, found := batches[partition]; !found {
			batches[partition], err = e.client.NewEventDataBatch(ctx, &batchOptions)
			if err != nil {
				return fmt.Errorf("creating batch for partition %q failed: %w", partition, err)
			}
		}

		// Add the event to the partition and send it if the batch is full
		err = batches[partition].AddEventData(&azeventhubs.EventData{Body: payload}, nil)
		if err == nil {
			continue
		}

		// If the event doesn't fit into the batch anymore, send the batch
		if !errors.Is(err, azeventhubs.ErrEventDataTooLarge) {
			return fmt.Errorf("adding metric to batch for partition %q failed: %w", partition, err)
		}

		// The event is larger than the maximum allowed size so there
		// is nothing we can do here but have to drop the metric.
		if batches[partition].NumEvents() == 0 {
			e.Log.Errorf("Metric with %d bytes exceeds the maximum allowed size and must be dropped!", len(payload))
			e.Log.Tracef("metric: %+v", m)
			continue
		}
		if err := e.send(batches[partition]); err != nil {
			return fmt.Errorf("sending batch for partition %q failed: %w", partition, err)
		}

		// Create a new metric and reiterate over the current metric to be
		// added in the next iteration of the for loop.
		batches[partition], err = e.client.NewEventDataBatch(ctx, &e.options)
		if err != nil {
			return fmt.Errorf("creating batch for partition %q failed: %w", partition, err)
		}
		i--
	}

	// Send the remaining batches that never exceeded the batch size
	for partition, batch := range batches {
		if batch.NumBytes() == 0 {
			continue
		}
		if err := e.send(batch); err != nil {
			return fmt.Errorf("sending batch for partition %q failed: %w", partition, err)
		}
	}
	return nil
}

func (e *EventHubs) send(batch *azeventhubs.EventDataBatch) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(e.Timeout))
	defer cancel()

	return e.client.SendEventDataBatch(ctx, batch, nil)
}

func init() {
	outputs.Add("event_hubs", func() telegraf.Output {
		return &EventHubs{
			Timeout: config.Duration(30 * time.Second),
		}
	})
}
