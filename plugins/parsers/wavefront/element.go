package wavefront

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
)

var (
	errInvalidTimestamp = errors.New("invalid timestamp")
)

type elementParser interface {
	parse(p *PointParser, pt *Point) error
}

type nameParser struct{}
type valueParser struct{}
type timestampParser struct {
	optional bool
}
type whiteSpaceParser struct {
	nextOptional bool
}
type tagParser struct{}
type loopedParser struct {
	wrappedParser elementParser
	wsParser      *whiteSpaceParser
}

func (*nameParser) parse(p *PointParser, pt *Point) error {
	// Valid characters are: a-z, A-Z, 0-9, hyphen ("-"), underscore ("_"), dot (".").
	// Forward slash ("/") and comma (",") are allowed if metricName is enclosed in double quotes.
	// Delta (U+2206) is allowed as the first character of the
	// metricName
	name, err := parseLiteral(p)

	if err != nil {
		return err
	}
	pt.Name = name
	return nil
}

func (*valueParser) parse(p *PointParser, pt *Point) error {
	tok, lit := p.scan()
	if tok == EOF {
		return fmt.Errorf("found %q, expected number", lit)
	}

	p.writeBuf.Reset()
	if tok == MinusSign {
		p.writeBuf.WriteString(lit)
		tok, lit = p.scan()
	}

	for tok != EOF && (tok == Letter || tok == Number || tok == Dot || tok == MinusSign) {
		p.writeBuf.WriteString(lit)
		tok, lit = p.scan()
	}
	p.unscan()

	pt.Value = p.writeBuf.String()
	if _, err := strconv.ParseFloat(pt.Value, 64); err != nil {
		return fmt.Errorf("invalid metric value %s", pt.Value)
	}
	return nil
}

func (ep *timestampParser) parse(p *PointParser, pt *Point) error {
	tok, lit := p.scan()
	if tok == EOF {
		if ep.optional {
			p.unscanTokens(2)
			return setTimestamp(pt, 0, 1)
		}
		return fmt.Errorf("found %q, expected number", lit)
	}

	if tok != Number {
		if ep.optional {
			p.unscanTokens(2)
			return setTimestamp(pt, 0, 1)
		}
		return errInvalidTimestamp
	}

	p.writeBuf.Reset()
	for tok == Number {
		p.writeBuf.WriteString(lit)
		tok, lit = p.scan()
	}
	p.unscan()

	tsStr := p.writeBuf.String()
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return err
	}
	return setTimestamp(pt, ts, len(tsStr))
}

func setTimestamp(pt *Point, ts int64, numDigits int) error {
	if numDigits == 19 {
		// nanoseconds
		ts = ts / 1e9
	} else if numDigits == 16 {
		// microseconds
		ts = ts / 1e6
	} else if numDigits == 13 {
		// milliseconds
		ts = ts / 1e3
	} else if numDigits != 10 {
		// must be in seconds, return error if not 0
		if ts != 0 {
			return errInvalidTimestamp
		}
		ts = getCurrentTime()
	}
	pt.Timestamp = ts
	return nil
}

func (ep *loopedParser) parse(p *PointParser, pt *Point) error {
	for {
		err := ep.wrappedParser.parse(p, pt)
		if err != nil {
			return err
		}
		err = ep.wsParser.parse(p, pt)
		if errors.Is(err, io.EOF) {
			break
		}
	}
	return nil
}

func (*tagParser) parse(p *PointParser, pt *Point) error {
	k, err := parseLiteral(p)
	if err != nil {
		if k == "" {
			return nil
		}
		return err
	}

	next, lit := p.scan()
	if next != Equals {
		return fmt.Errorf("found %q, expected equals", lit)
	}

	v, err := parseLiteral(p)
	if err != nil {
		return err
	}
	if len(pt.Tags) == 0 {
		pt.Tags = make(map[string]string)
	}
	pt.Tags[k] = v
	return nil
}

func (ep *whiteSpaceParser) parse(p *PointParser, _ *Point) error {
	tok := Ws
	for tok == Ws {
		tok, _ = p.scan()
	}

	if tok == EOF {
		if !ep.nextOptional {
			return io.EOF
		}
		return nil
	}
	p.unscan()
	return nil
}

func parseQuotedLiteral(p *PointParser) (string, error) {
	p.writeBuf.Reset()

	escaped := false
	tok, lit := p.scan()
	for tok != EOF && (tok != Quotes || (tok == Quotes && escaped)) {
		// let everything through
		escaped = tok == Backslash
		p.writeBuf.WriteString(lit)
		tok, lit = p.scan()
	}
	if tok == EOF {
		return "", fmt.Errorf("found %q, expected quotes", lit)
	}
	return p.writeBuf.String(), nil
}

func parseLiteral(p *PointParser) (string, error) {
	tok, lit := p.scan()
	if tok == EOF {
		return "", fmt.Errorf("found %q, expected literal", lit)
	}

	if tok == Quotes {
		return parseQuotedLiteral(p)
	}

	p.writeBuf.Reset()
	for tok != EOF && tok > literalBeg && tok < literalEnd {
		p.writeBuf.WriteString(lit)
		tok, lit = p.scan()
		if tok == Delta {
			return "", errors.New("found delta inside metric name")
		}
	}
	if tok == Quotes {
		return "", errors.New("found quote inside unquoted literal")
	}
	p.unscan()
	return p.writeBuf.String(), nil
}

func getCurrentTime() int64 {
	return time.Now().UnixNano() / 1e9
}
