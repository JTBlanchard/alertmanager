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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/log"
	commoncfg "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/notify/test"
	"github.com/prometheus/alertmanager/types"
)

func TestWebexRetry(t *testing.T) {
	notifier, err := New(
		&config.WebexConfig{
			APIToken:   config.Secret("01234567890123456789012345678901"),
			HTTPConfig: &commoncfg.HTTPClientConfig{},
		},
		test.CreateTmpl(t),
		log.NewNopLogger(),
	)
	require.NoError(t, err)

	retryCodes := append(test.DefaultRetryCodes(), http.StatusTooManyRequests)
	for statusCode, expected := range test.RetryTests(retryCodes) {
		actual, _ := notifier.retrier.Check(statusCode, nil)
		require.Equal(t, expected, actual, fmt.Sprintf("retry - error on status %d", statusCode))
	}
}

func TestWebexRedactedURL(t *testing.T) {
	ctx, u, fn := test.GetContextWithCancelingURL()
	defer fn()

	key := "01234567890123456789012345678901"
	notifier, err := New(
		&config.WebexConfig{
			APIURL:        &config.URL{URL: u},
			APIToken:      config.Secret(key),
			HTTPConfig:    &commoncfg.HTTPClientConfig{},
			ToPersonEmail: "foo@bar.com",
		},
		test.CreateTmpl(t),
		log.NewNopLogger(),
	)
	require.NoError(t, err)

	test.AssertNotifyLeaksNoSecret(t, ctx, notifier, key)
}

func TestWebexTemplating(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dec := json.NewDecoder(r.Body)
		out := make(map[string]interface{})
		err := dec.Decode(&out)
		if err != nil {
			panic(err)
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	for _, tc := range []struct {
		title string
		cfg   *config.WebexConfig

		retry  bool
		errMsg string
	}{
		{
			title: "full-blown message",
			cfg: &config.WebexConfig{
				APIToken:      config.Secret("01234567890123456789012345678901"),
				ToPersonEmail: "foo@bar.com",
			},
		},
		{
			title: "message with templating errors",
			cfg: &config.WebexConfig{
				APIToken:      config.Secret("01234567890123456789012345678901"),
				ToPersonEmail: "foo@bar.com",
				Markdown:      "{{ ",
			},
			errMsg: "failed to template",
		},
		{
			title: "recipient required",
			cfg: &config.WebexConfig{
				APIToken: config.Secret("01234567890123456789012345678901"),
			},
			errMsg: "one of room_id, to_person_id, or to_person_email required",
		},
	} {
		t.Run(tc.title, func(t *testing.T) {
			tc.cfg.APIURL = &config.URL{URL: u}
			tc.cfg.HTTPConfig = &commoncfg.HTTPClientConfig{}
			pd, err := New(tc.cfg, test.CreateTmpl(t), log.NewNopLogger())
			require.NoError(t, err)

			ctx := context.Background()
			ctx = notify.WithGroupKey(ctx, "1")

			ok, err := pd.Notify(ctx, []*types.Alert{
				&types.Alert{
					Alert: model.Alert{
						Labels: model.LabelSet{
							"lbl1": "val1",
						},
						StartsAt: time.Now(),
						EndsAt:   time.Now().Add(time.Hour),
					},
				},
			}...)
			if tc.errMsg == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errMsg)
			}
			require.Equal(t, tc.retry, ok)
		})
	}
}
func TestMessageSizeEnforcement(t *testing.T) {
	bigDetails := strings.Repeat("a", 513000)

	msg := &WebexMessage{
		Markdown: bigDetails,
	}

	notifier, err := New(
		&config.WebexConfig{
			APIToken:   config.Secret("01234567890123456789012345678901"),
			HTTPConfig: &commoncfg.HTTPClientConfig{},
		},
		test.CreateTmpl(t),
		log.NewNopLogger(),
	)
	require.NoError(t, err)

	encoded, err := notifier.encodeMessage(msg)
	require.NoError(t, err)
	require.Contains(t, encoded.String(), `{"markdown":"Custom details have been removed because the original message exceeds the maximum size of 7439 bytes"}`)

}
