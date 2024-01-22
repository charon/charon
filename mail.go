package charon

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	tt "text/template"

	"github.com/rs/zerolog"
	"github.com/wneessen/go-mail"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
)

var MailAuthTypes = map[string]mail.SMTPAuthType{} //nolint:gochecknoglobals

func init() { //nolint:gochecknoinits
	for _, a := range []mail.SMTPAuthType{mail.SMTPAuthLogin, mail.SMTPAuthPlain, mail.SMTPAuthCramMD5, mail.SMTPAuthXOAUTH2} {
		MailAuthTypes[strings.ToLower(string(a))] = a
	}
}

func (s *Service) sendMail(ctx context.Context, flow *Flow, to, subject string, body *tt.Template, data interface{}) errors.E {
	logger := zerolog.Ctx(ctx)
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
	if s.mailClient != nil {
		err = s.mailClient.DialAndSendWithContext(ctx, m)
		if err != nil {
			return errors.WithStack(err)
		}
		logger.Debug().Str("messageID", messageID).Msg("e-mail sent")
		return nil
	}
	buffer := new(bytes.Buffer)
	_, err = m.WriteTo(buffer)
	if err != nil {
		return errors.WithStack(err)
	}
	logger.Info().Str("messageID", messageID).Str("mail", buffer.String()).Msg("e-mail sending not configured")
	return nil
}

type loggerAdapter struct {
	Logger zerolog.Logger
}

func (l loggerAdapter) Debugf(format string, v ...interface{}) {
	l.Logger.Debug().Msgf(format, v...)
}

func (l loggerAdapter) Errorf(format string, v ...interface{}) {
	l.Logger.Error().Msgf(format, v...)
}

func (l loggerAdapter) Infof(format string, v ...interface{}) {
	l.Logger.Info().Msgf(format, v...)
}

func (l loggerAdapter) Warnf(format string, v ...interface{}) {
	l.Logger.Warn().Msgf(format, v...)
}
