package charon

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	tt "text/template"

	"github.com/rs/zerolog"
	"github.com/wneessen/go-mail"
	"github.com/wneessen/go-mail/log"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
	"gitlab.com/tozd/waf"
)

var MailAuthTypes = map[string]mail.SMTPAuthType{} //nolint:gochecknoglobals

func init() { //nolint:gochecknoinits
	MailAuthTypes["none"] = mail.SMTPAuthNoAuth
	for _, a := range []mail.SMTPAuthType{mail.SMTPAuthLogin, mail.SMTPAuthPlain, mail.SMTPAuthCramMD5, mail.SMTPAuthXOAUTH2} {
		MailAuthTypes[strings.ToLower(string(a))] = a
	}
}

func (s *Service) sendMail(ctx context.Context, flow *Flow, emails []string, subject string, body *tt.Template, data interface{}) errors.E {
	logger := zerolog.Ctx(ctx)
	ms := []*mail.Msg{}
	for _, to := range emails {
		m := mail.NewMsg()
		id := identifier.New()
		messageID := fmt.Sprintf("%s.%s@%s", id, flow.ID, s.domain)
		m.SetMessageIDWithValue(messageID)
		err := m.From(s.mailFrom)
		if err != nil {
			return errors.WithStack(err)
		}
		err = m.To(to)
		if err != nil {
			return errors.WithStack(err)
		}
		m.Subject(subject)
		err = m.SetBodyTextTemplate(body, data)
		if err != nil {
			return errors.WithStack(err)
		}
		// By setting X-Entity-Ref-ID to a random value, Gmail does not combine
		// similar e-mails into one thread.
		m.SetGenHeader("X-Entity-Ref-ID", id.String())
		site := waf.MustGetSite[*Site](ctx)
		if site.Build != nil {
			m.SetUserAgent(fmt.Sprintf("Charon version %s (build on %s, git revision %s)", site.Build.Version, site.Build.BuildTimestamp, site.Build.Revision))
		} else {
			m.SetUserAgent("Charon")
		}
		ms = append(ms, m)
	}

	// If we have a mail client, we can send e-mails.
	if s.mailClient != nil {
		err := s.mailClient.DialWithContext(ctx)
		if err != nil {
			return errors.WithStack(err)
		}
		defer s.mailClient.Close()

		// We loop over all e-mails ourselves to know if sending failed and to have better errors structure.
		// See: https://github.com/wneessen/go-mail/issues/166
		errs := []error{}
		for _, m := range ms {
			err := s.mailClient.Send(m)
			errs = append(errs, err)
			if err == nil {
				messageID := strings.Trim(m.GetGenHeader(mail.HeaderMessageID)[0], "<>")
				logger.Debug().Str("messageID", messageID).Msg("e-mail sent")
			}
		}

		return errors.Join(errs...)
	}

	// Otherwise we just log them.
	buffer := new(bytes.Buffer)
	for _, m := range ms {
		_, err := m.WriteTo(buffer)
		if err != nil {
			return errors.WithStack(err)
		}
		messageID := strings.Trim(m.GetGenHeader(mail.HeaderMessageID)[0], "<>")
		// TODO: Log mail in the way that console formatter formats it after the log line.
		logger.Info().Str("messageID", messageID).Str("mail", buffer.String()).Msg("e-mail sending not configured")
		buffer.Reset()
	}

	return nil
}

type loggerAdapter struct {
	Logger zerolog.Logger
}

func (l loggerAdapter) direction(entry log.Log) string {
	p := "client"
	if entry.Direction == log.DirClientToServer {
		p = "server"
	}
	return p
}

func (l loggerAdapter) Debugf(entry log.Log) {
	l.Logger.Debug().Str("to", l.direction(entry)).Msgf(entry.Format, entry.Messages...)
}

func (l loggerAdapter) Errorf(entry log.Log) {
	l.Logger.Error().Str("to", l.direction(entry)).Msgf(entry.Format, entry.Messages...)
}

func (l loggerAdapter) Infof(entry log.Log) {
	l.Logger.Info().Str("to", l.direction(entry)).Msgf(entry.Format, entry.Messages...)
}

func (l loggerAdapter) Warnf(entry log.Log) {
	l.Logger.Warn().Str("to", l.direction(entry)).Msgf(entry.Format, entry.Messages...)
}
