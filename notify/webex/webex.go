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

// maxMessageSize represents the maximum message body size in bytes.
const maxMessageSize = 7439

// Notify implements the Webex Notifier interface.
func (n *Notifier) Notify(ctx context.Context, alerts ...*types.Alert) (bool, error) {
	req, retry, err := n.createRequest(ctx, alerts...)
	if err != nil {
		return retry, err
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return true, err
	}
	defer notify.Drain(resp)

	retry, err = n.retrier.Check(resp.StatusCode, resp.Request.Body)
	return retry, err
}

func (n *Notifier) createRequest(ctx context.Context, alerts ...*types.Alert) (*http.Request, bool, error) {
	groupKey, err := notify.ExtractGroupKey(ctx)
	if err != nil {
		return nil, false, err
	}
	level.Debug(n.logger).Log("notification", groupKey, "RoomID", n.conf.RoomID, "ToPersonID", n.conf.ToPersonID, n.conf.ToPersonEmail)

	data := notify.GetTemplateData(ctx, n.tmpl, alerts, n.logger)
	tmpl := notify.TmplText(n.tmpl, data, &err)
	if err != nil {
		return nil, false, errors.Wrap(err, "failed to template")
	}
	level.Info(n.logger).Log("data", "%+v", data)
	fmt.Printf("%+v", data)

	markdown, truncated := notify.Truncate(tmpl(n.conf.Markdown), maxMessageSize)
	if truncated {
		level.Debug(n.logger).Log("msg", "truncated Markdown message", "truncated_message", markdown, "alert", groupKey)
	}
	text, truncated := notify.Truncate(tmpl(n.conf.Text), maxMessageSize)
	if truncated {
		level.Debug(n.logger).Log("msg", "truncated Text message", "truncated_message", text, "alert", groupKey)
	}

	msg := &WebexMessage{
		RoomID:        n.conf.RoomID,
		ToPersonID:    n.conf.ToPersonID,
		ToPersonEmail: n.conf.ToPersonEmail,
		Markdown:      markdown,
		Text:          text,
		Files:         nil,
		Attachments:   nil,
	}

	postMessageURL := n.conf.APIURL.Copy()
	postMessageURL.Path += "v1/messages"
	var buf bytes.Buffer
	level.Info(n.logger).Log("msg", "%+v", msg)
	if err := json.NewEncoder(&buf).Encode(msg); err != nil {
		return nil, false, err
	}
	req, err := http.NewRequest("POST", postMessageURL.String(), &buf)
	if err != nil {
		return nil, true, err
	}
	req.Header.Set("Authorization", "Bearer "+string(n.conf.APIToken))
	req.Header.Set("User-Agent", notify.UserAgentHeader)
	req.Header.Set("Content-Type", "application/json")

	return req, true, nil

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
