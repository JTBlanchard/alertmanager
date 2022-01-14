// Copyright 2019 Prometheus Team
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package webex

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/alecthomas/units"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/pkg/errors"
	commoncfg "github.com/prometheus/common/config"

	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/template"
	"github.com/prometheus/alertmanager/types"
)

// Notifier implements a Notifier for Webex notifications.
type Notifier struct {
	conf    *config.WebexConfig
	tmpl    *template.Template
	logger  log.Logger
	client  *http.Client
	retrier *notify.Retrier
}

// New returns a new Webex notifier.
func New(c *config.WebexConfig, t *template.Template, l log.Logger, httpOpts ...commoncfg.HTTPClientOption) (*Notifier, error) {
	client, err := commoncfg.NewClientFromConfig(*c.HTTPConfig, "webex", httpOpts...)
	if err != nil {
		return nil, err
	}

	notifier := &Notifier{
		conf:    c,
		tmpl:    t,
		logger:  l,
		client:  client,
		retrier: &notify.Retrier{RetryCodes: []int{http.StatusTooManyRequests}, CustomDetailsFunc: errDetails}}

	return notifier, nil
}

type WebexMessage struct {
	RoomID        string            `json:"roomId,omitempty"`        // Room ID.
	ToPersonID    string            `json:"toPersonId,omitempty"`    // Person ID (for type=direct).
	ToPersonEmail string            `json:"toPersonEmail,omitempty"` // Person email (for type=direct).
	Text          string            `json:"text,omitempty"`          // Message in plain text format.
	Markdown      string            `json:"markdown,omitempty"`      // Message in markdown format.
	Files         []string          `json:"files,omitempty"`         // File URL array.
	Attachments   []WebexAttachment `json:"attachments,omitempty"`   //Attachment Array
}

type WebexAttachment struct {
	Content     map[string]interface{} `json:"content"`
	ContentType string                 `json:"contentType"`
}

// maxMessageSize represents the maximum size in bytes.
const maxMessageSize = 7439

func (n *Notifier) encodeMessage(msg *WebexMessage) (bytes.Buffer, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(msg); err != nil {
		return buf, errors.Wrap(err, "failed to encode Webex message")
	}

	if buf.Len() > maxMessageSize {
		truncatedMsg := fmt.Sprintf("Custom details have been removed because the original message exceeds the maximum size of %d bytes", maxMessageSize)

		msg.Markdown = truncatedMsg

		warningMsg := fmt.Sprintf("Truncated Details because message of size %s exceeds limit %d bytes", units.MetricBytes(buf.Len()).String(), maxMessageSize)
		level.Warn(n.logger).Log("msg", warningMsg)

		buf.Reset()
		if err := json.NewEncoder(&buf).Encode(msg); err != nil {
			return buf, errors.Wrap(err, "failed to encode Webex message")
		}
	}

	return buf, nil
}

// Notify implements the Webex Notifier interface.
func (n *Notifier) Notify(ctx context.Context, alerts ...*types.Alert) (bool, error) {
	var (
		tmplErr error
		data    = notify.GetTemplateData(ctx, n.tmpl, alerts, n.logger)
		tmpl    = notify.TmplText(n.tmpl, data, &tmplErr)
	)
	if tmplErr != nil {
		return false, errors.Wrap(tmplErr, "failed to template")
	}

	groupKey, err := notify.ExtractGroupKey(ctx)
	if err != nil {
		level.Error(n.logger).Log("err", err)
	}

	level.Debug(n.logger).Log("notification", groupKey, "RoomID", n.conf.RoomID, "ToPersonID", n.conf.ToPersonID, n.conf.ToPersonEmail)

	msg := &WebexMessage{
		RoomID:        tmpl(n.conf.RoomID),
		ToPersonID:    tmpl(n.conf.ToPersonID),
		ToPersonEmail: tmpl(n.conf.ToPersonEmail),
		Text:          tmpl(n.conf.Text),
		Markdown:      tmpl(n.conf.Markdown),
		Files:         nil,
		Attachments:   nil,
	}

	// Check for valid recipient
	if msg.RoomID == "" && msg.ToPersonID == "" && msg.ToPersonEmail == "" {
		return false, errors.New("one of room_id, to_person_id, or to_person_email required")
	}

	postMessageURL := n.conf.APIURL.Copy()
	postMessageURL.Path += "message/send"
	q := postMessageURL.Query()
	q.Set("access_token", string(n.conf.APIToken))
	postMessageURL.RawQuery = q.Encode()

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(msg); err != nil {
		return false, err
	}

	resp, err := notify.PostJSON(ctx, n.client, postMessageURL.String(), &buf)
	if err != nil {
		return true, err
	}
	notify.Drain(resp)

	return n.retrier.Check(resp.StatusCode, nil)
}

func errDetails(status int, body io.Reader) string {
	if status != http.StatusBadRequest || body == nil {
		return ""
	}
	var pgr struct {
		Status  string   `json:"status"`
		Message string   `json:"message"`
		Errors  []string `json:"errors"`
	}
	if err := json.NewDecoder(body).Decode(&pgr); err != nil {
		return ""
	}
	return fmt.Sprintf("%s: %s", pgr.Message, strings.Join(pgr.Errors, ","))
}
