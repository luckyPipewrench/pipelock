// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/url"
	"reflect"
	"strings"
	"time"
)

const (
	ocsfSchemaVersion = "1.8.0"

	ocsfCategoryUIDFindings       = 2
	ocsfCategoryNameFindings      = "Findings"
	ocsfClassUIDDetectionFinding  = 2004
	ocsfClassNameDetectionFinding = "Detection Finding"
	ocsfActivityIDCreate          = 1
	ocsfActivityNameCreate        = "Create"
	ocsfStatusIDNew               = 1
	ocsfStatusNew                 = "New"
)

type ocsfDetectionFinding struct {
	ActivityID   int                  `json:"activity_id"`
	ActivityName string               `json:"activity_name"`
	CategoryUID  int                  `json:"category_uid"`
	CategoryName string               `json:"category_name"`
	ClassUID     int                  `json:"class_uid"`
	ClassName    string               `json:"class_name"`
	TypeUID      int                  `json:"type_uid"`
	TypeName     string               `json:"type_name"`
	SeverityID   int                  `json:"severity_id"`
	Severity     string               `json:"severity"`
	Time         int64                `json:"time"`
	Message      string               `json:"message"`
	Metadata     ocsfMetadata         `json:"metadata"`
	StatusID     int                  `json:"status_id"`
	Status       string               `json:"status"`
	FindingInfo  ocsfFindingInfo      `json:"finding_info"`
	ActionID     int                  `json:"action_id,omitempty"`
	Action       string               `json:"action,omitempty"`
	Actor        *ocsfActor           `json:"actor,omitempty"`
	SrcEndpoint  *ocsfNetworkEndpoint `json:"src_endpoint,omitempty"`
	DstEndpoint  *ocsfNetworkEndpoint `json:"dst_endpoint,omitempty"`
	URL          *ocsfURL             `json:"url,omitempty"`
	HTTPRequest  *ocsfHTTPRequest     `json:"http_request,omitempty"`
	StatusDetail string               `json:"status_detail,omitempty"`
	Unmapped     map[string]any       `json:"unmapped,omitempty"`
}

type ocsfMetadata struct {
	Version string      `json:"version"`
	Product ocsfProduct `json:"product"`
}

type ocsfProduct struct {
	VendorName string `json:"vendor_name"`
	Name       string `json:"name"`
	Version    string `json:"version"`
}

type ocsfFindingInfo struct {
	UID         string      `json:"uid"`
	Title       string      `json:"title"`
	Description string      `json:"desc,omitempty"`
	Product     ocsfProduct `json:"product"`
	CreatedTime int64       `json:"created_time"`
}

type ocsfActor struct {
	User ocsfUser `json:"user"`
}

type ocsfUser struct {
	Name string `json:"name"`
}

type ocsfNetworkEndpoint struct {
	IP       string `json:"ip,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Port     int    `json:"port,omitempty"`
}

type ocsfURL struct {
	URLString   string `json:"url_string"`
	Scheme      string `json:"scheme,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	Port        int    `json:"port,omitempty"`
	Path        string `json:"path,omitempty"`
	QueryString string `json:"query_string,omitempty"`
}

type ocsfHTTPRequest struct {
	HTTPMethod string `json:"http_method,omitempty"`
	UID        string `json:"uid,omitempty"`
}

// FormatOCSFEvent renders a Pipelock audit event as one OCSF Detection Finding.
// Pipelock events are scanner and policy decisions on mediated activity, so the
// Findings category preserves the security judgment while typed network fields
// capture request context when the source event has it.
func FormatOCSFEvent(event Event, deviceVersion string) string {
	if deviceVersion == "" {
		deviceVersion = "unknown"
	}

	eventTime := event.Timestamp.UTC()
	millis := eventTime.UnixMilli()
	severityID, severityName := ocsfSeverity(event.Severity)
	product := ocsfProduct{
		VendorName: "Pipelock",
		Name:       "Pipelock",
		Version:    deviceVersion,
	}
	action := eventAction(event)
	decisionType := eventDecisionType(event)

	record := ocsfDetectionFinding{
		ActivityID:   ocsfActivityIDCreate,
		ActivityName: ocsfActivityNameCreate,
		CategoryUID:  ocsfCategoryUIDFindings,
		CategoryName: ocsfCategoryNameFindings,
		ClassUID:     ocsfClassUIDDetectionFinding,
		ClassName:    ocsfClassNameDetectionFinding,
		TypeUID:      ocsfClassUIDDetectionFinding*100 + ocsfActivityIDCreate,
		TypeName:     ocsfClassNameDetectionFinding + ": " + ocsfActivityNameCreate,
		SeverityID:   severityID,
		Severity:     severityName,
		Time:         millis,
		Message:      cefName(event),
		Metadata: ocsfMetadata{
			Version: ocsfSchemaVersion,
			Product: product,
		},
		StatusID: ocsfStatusIDNew,
		Status:   ocsfStatusNew,
		FindingInfo: ocsfFindingInfo{
			UID:         ocsfFindingUID(event),
			Title:       cefName(event),
			Description: ocsfStringField(event.Fields, fieldReason, "error"),
			Product:     product,
			CreatedTime: millis,
		},
		ActionID:     ocsfActionID(action),
		Action:       action,
		Actor:        ocsfActorFromEvent(event),
		SrcEndpoint:  ocsfEndpointFromValue(ocsfStringField(event.Fields, "client_ip")),
		DstEndpoint:  ocsfDstEndpointFromEvent(event),
		URL:          ocsfURLFromEvent(event),
		HTTPRequest:  ocsfHTTPRequestFromEvent(event),
		StatusDetail: ocsfStringField(event.Fields, fieldReason, "error"),
		Unmapped: map[string]any{
			"pipelock": map[string]any{
				"event_type":    event.Type,
				"severity":      event.Severity.String(),
				"instance_id":   event.InstanceID,
				"action":        action,
				"decision_type": decisionType,
				"fields":        ocsfJSONValue(event.Fields),
			},
		},
	}

	if record.ActionID == 0 {
		record.Action = ""
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(record); err != nil {
		return fallbackOCSFEvent(record, err)
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

func fallbackOCSFEvent(record ocsfDetectionFinding, err error) string {
	eventType := record.FindingInfo.Title
	if pipelock, ok := record.Unmapped["pipelock"].(map[string]any); ok {
		if value, ok := pipelock["event_type"].(string); ok && value != "" {
			eventType = value
		}
	}
	record.Message = "ocsf_format_error: " + record.Message
	record.StatusDetail = err.Error()
	record.Actor = nil
	record.SrcEndpoint = nil
	record.DstEndpoint = nil
	record.URL = nil
	record.HTTPRequest = nil
	record.Unmapped = map[string]any{
		"pipelock": map[string]any{
			"event_type":        eventType,
			"ocsf_format_error": err.Error(),
		},
	}

	msg, marshalErr := json.Marshal(record)
	if marshalErr != nil {
		return `{"activity_id":1,"activity_name":"Create","category_uid":2,"category_name":"Findings","class_uid":2004,"class_name":"Detection Finding","type_uid":200401,"type_name":"Detection Finding: Create","severity_id":0,"severity":"Unknown","time":0,"message":"ocsf_format_error","metadata":{"version":"1.8.0","product":{"vendor_name":"Pipelock","name":"Pipelock","version":"unknown"}},"status_id":1,"status":"New","finding_info":{"uid":"ocsf-format-error","title":"ocsf_format_error","product":{"vendor_name":"Pipelock","name":"Pipelock","version":"unknown"},"created_time":0}}`
	}
	return string(msg)
}

func ocsfSeverity(sev Severity) (int, string) {
	switch sev {
	case SeverityInfo:
		return 1, "Informational"
	case SeverityWarn:
		return 3, "Medium"
	case SeverityCritical:
		return 5, "Critical"
	default:
		return 0, "Unknown"
	}
}

func ocsfActionID(action string) int {
	switch action {
	case conventionActionAllow, eventActionForward, EventRedirect:
		return 1
	case conventionActionBlock, eventActionStrip:
		return 2
	case conventionActionWarn, conventionActionAsk, eventActionDefer:
		return 99
	default:
		return 0
	}
}

func ocsfActorFromEvent(event Event) *ocsfActor {
	agent := eventAgent(event)
	if agent == "" {
		return nil
	}
	return &ocsfActor{User: ocsfUser{Name: agent}}
}

func ocsfURLFromEvent(event Event) *ocsfURL {
	raw := ocsfStringField(event.Fields, "url")
	if raw == "" {
		return nil
	}
	out := &ocsfURL{URLString: raw}
	parsed, err := url.Parse(raw)
	if err != nil {
		return out
	}
	out.Scheme = parsed.Scheme
	out.Hostname = parsed.Hostname()
	out.Path = parsed.Path
	out.QueryString = parsed.RawQuery
	if port := parsed.Port(); port != "" {
		_, _ = fmt.Sscan(port, &out.Port)
	}
	return out
}

func ocsfHTTPRequestFromEvent(event Event) *ocsfHTTPRequest {
	req := ocsfHTTPRequest{
		HTTPMethod: ocsfStringField(event.Fields, "method"),
		UID:        ocsfStringField(event.Fields, "request_id"),
	}
	if req.HTTPMethod == "" && req.UID == "" {
		return nil
	}
	return &req
}

func ocsfDstEndpointFromEvent(event Event) *ocsfNetworkEndpoint {
	if eventURL := ocsfURLFromEvent(event); eventURL != nil && eventURL.Hostname != "" {
		return &ocsfNetworkEndpoint{Hostname: eventURL.Hostname, Port: eventURL.Port}
	}
	return ocsfEndpointFromValue(ocsfStringField(event.Fields, "target", "resource"))
}

func ocsfEndpointFromValue(value string) *ocsfNetworkEndpoint {
	if value == "" {
		return nil
	}
	endpoint := &ocsfNetworkEndpoint{}
	if ip := net.ParseIP(value); ip != nil {
		endpoint.IP = ip.String()
		return endpoint
	}
	endpoint.Hostname = value
	return endpoint
}

func ocsfStringField(fields map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := fields[key]
		if !ok {
			continue
		}
		rendered := cefFieldValue(value)
		if rendered != "" {
			return rendered
		}
	}
	return ""
}

func ocsfFindingUID(event Event) string {
	sum := sha256.New()
	_, _ = fmt.Fprintf(sum, "%s|%s|%s|", event.InstanceID, event.Type, event.Timestamp.UTC().Format(time.RFC3339Nano))
	fields, err := json.Marshal(ocsfJSONValue(event.Fields))
	if err == nil {
		_, _ = sum.Write(fields)
	}
	return hex.EncodeToString(sum.Sum(nil))
}

func ocsfJSONValue(value any) any {
	return ocsfJSONValueDepth(value, 0)
}

func ocsfJSONValueDepth(value any, depth int) any {
	if depth > 16 {
		return "[truncated]"
	}

	switch v := value.(type) {
	case nil:
		return nil
	case string, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return v
	case float32:
		if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
			return fmt.Sprint(v)
		}
		return v
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Sprint(v)
		}
		return v
	case fmt.Stringer:
		return v.String()
	case []string:
		out := make([]string, len(v))
		copy(out, v)
		return out
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, ocsfJSONValueDepth(item, depth+1))
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = ocsfJSONValueDepth(item, depth+1)
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = item
		}
		return out
	}

	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		out := make([]any, 0, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			out = append(out, ocsfJSONValueDepth(rv.Index(i).Interface(), depth+1))
		}
		return out
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return "[unsupported]"
		}
		out := make(map[string]any, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			out[iter.Key().String()] = ocsfJSONValueDepth(iter.Value().Interface(), depth+1)
		}
		return out
	default:
		return fmt.Sprint(value)
	}
}
