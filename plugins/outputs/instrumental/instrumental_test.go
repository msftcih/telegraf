package instrumental

import (
	"bufio"
	"io"
	"net"
	"net/textproto"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/metric"
)

func TestWrite(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	port := TCPServer(t, &wg)

	i := Instrumental{
		Host:     "127.0.0.1",
		Port:     port,
		APIToken: config.NewSecret([]byte("abc123token")),
		Prefix:   "my.prefix",
	}
	require.NoError(t, i.Init())

	// Default to gauge
	m1 := metric.New(
		"mymeasurement",
		map[string]string{"host": "192.168.0.1"},
		map[string]interface{}{"myfield": float64(3.14)},
		time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC),
	)
	m2 := metric.New(
		"mymeasurement",
		map[string]string{"host": "192.168.0.1", "metric_type": "set"},
		map[string]interface{}{"value": float64(3.14)},
		time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC),
	)

	metrics := []telegraf.Metric{m1, m2}
	err := i.Write(metrics)
	require.NoError(t, err)

	// Counter and Histogram are increments
	m3 := metric.New(
		"my_histogram",
		map[string]string{"host": "192.168.0.1", "metric_type": "histogram"},
		map[string]interface{}{"value": float64(3.14)},
		time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC),
	)
	// We will modify metric names that won't be accepted by Instrumental
	m4 := metric.New(
		"bad_metric_name",
		map[string]string{"host": "192.168.0.1:8888::123", "metric_type": "counter"},
		map[string]interface{}{"value": 1},
		time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC),
	)
	// We will drop metric values that won't be accepted by Instrumental
	m5 := metric.New(
		"bad_values",
		map[string]string{"host": "192.168.0.1", "metric_type": "counter"},
		map[string]interface{}{"value": "\" 3:30\""},
		time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC),
	)
	m6 := metric.New(
		"my_counter",
		map[string]string{"host": "192.168.0.1", "metric_type": "counter"},
		map[string]interface{}{"value": float64(3.14)},
		time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC),
	)

	metrics = []telegraf.Metric{m3, m4, m5, m6}
	err = i.Write(metrics)
	require.NoError(t, err)

	wg.Wait()
}

func TCPServer(t *testing.T, wg *sync.WaitGroup) int {
	tcpServer, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		defer wg.Done()
		conn, err := tcpServer.Accept()
		require.NoError(t, err)
		err = conn.SetDeadline(time.Now().Add(1 * time.Second))
		require.NoError(t, err)
		reader := bufio.NewReader(conn)
		tp := textproto.NewReader(reader)

		hello, err := tp.ReadLine()
		require.NoError(t, err)
		require.Equal(t, "hello version go/telegraf/1.1", hello)
		auth, err := tp.ReadLine()
		require.NoError(t, err)
		require.Equal(t, "authenticate abc123token", auth)
		_, err = conn.Write([]byte("ok\nok\n"))
		require.NoError(t, err)

		data1, err := tp.ReadLine()
		require.NoError(t, err)
		require.Equal(t, "gauge my.prefix.192_168_0_1.mymeasurement.myfield 3.14 1289430000", data1)
		data2, err := tp.ReadLine()
		require.NoError(t, err)
		require.Equal(t, "gauge my.prefix.192_168_0_1.mymeasurement 3.14 1289430000", data2)

		conn, err = tcpServer.Accept()
		require.NoError(t, err)
		err = conn.SetDeadline(time.Now().Add(1 * time.Second))
		require.NoError(t, err)
		reader = bufio.NewReader(conn)
		tp = textproto.NewReader(reader)

		hello, err = tp.ReadLine()
		require.NoError(t, err)
		require.Equal(t, "hello version go/telegraf/1.1", hello)
		auth, err = tp.ReadLine()
		require.NoError(t, err)
		require.Equal(t, "authenticate abc123token", auth)
		_, err = conn.Write([]byte("ok\nok\n"))
		require.NoError(t, err)

		data3, err := tp.ReadLine()
		require.NoError(t, err)
		require.Equal(t, "increment my.prefix.192_168_0_1.my_histogram 3.14 1289430000", data3)

		data4, err := tp.ReadLine()
		require.NoError(t, err)
		require.Equal(t, "increment my.prefix.192_168_0_1_8888_123.bad_metric_name 1 1289430000", data4)

		data5, err := tp.ReadLine()
		require.NoError(t, err)
		require.Equal(t, "increment my.prefix.192_168_0_1.my_counter 3.14 1289430000", data5)

		data6, err := tp.ReadLine()
		require.ErrorIs(t, err, io.EOF)
		require.Equal(t, "", data6)

		err = conn.Close()
		require.NoError(t, err)
	}()

	return tcpServer.Addr().(*net.TCPAddr).Port
}
