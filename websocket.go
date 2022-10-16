package textsecure

import (
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/gorilla/websocket"
	"github.com/signal-golang/textsecure/config"
	signalservice "github.com/signal-golang/textsecure/protobuf"
	"github.com/signal-golang/textsecure/registration"
	rootCa "github.com/signal-golang/textsecure/rootCa"
	log "github.com/sirupsen/logrus"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 25 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Signal websocket endpoint
	websocketPath = "/v1/websocket/"
)

// Conn is a wrapper for the websocket connection
type Conn struct {
	// The websocket connection
	ws *websocket.Conn

	// Buffered channel of outbound messages
	send chan []byte
}

var wsconn *Conn

// Connect to Signal websocket API at originURL with user and pass credentials
func (c *Conn) connect(originURL, user, pass string) error {
	v := url.Values{}
	v.Set("login", user)
	v.Set("password", pass)
	params := v.Encode()
	wsURL := strings.Replace(originURL, "http", "ws", 1) + "?" + params
	u, _ := url.Parse(wsURL)

	log.Debugf("[textsecure] Websocket Connecting to signal-server")
	// log.Debugf("Websocket Connecting to %s with user %s and pass %s", originURL, user, pass)

	var err error
	d := &websocket.Dialer{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	d.NetDial = func(network, addr string) (net.Conn, error) { return net.Dial(network, u.Host) }
	d.TLSClientConfig = &tls.Config{
		RootCAs: rootCa.RootCA,
	}

	c.ws, _, err = d.Dial(u.String(), nil)
	if err != nil {
		return err
	}

	log.Debugf("[textsecure] Websocket Connected successfully")

	return nil
}

// Send ack response message
func (c *Conn) sendAck(id uint64) error {
	typ := signalservice.WebSocketMessage_RESPONSE
	message := "OK"
	status := uint32(200)

	wsm := &signalservice.WebSocketMessage{
		Type: &typ,
		Response: &signalservice.WebSocketResponseMessage{
			Id:      &id,
			Status:  &status,
			Message: &message,
		},
	}

	b, err := proto.Marshal(wsm)
	if err != nil {
		return err
	}

	c.send <- b
	return nil
}

// write writes a message with the given message type and payload.
func (c *Conn) write(mt int, payload []byte) error {
	c.ws.SetWriteDeadline(time.Now().Add(writeWait))
	return c.ws.WriteMessage(mt, payload)
}

// writeWorker writes messages to websocket connection
func (c *Conn) writeWorker() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		log.Debugf("[textsecure] Closing writeWorker")
		ticker.Stop()
		c.ws.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				log.Errorf("[textsecure] Failed to read message from channel")
				c.write(websocket.CloseMessage, []byte{})
				return
			}

			log.Debugf("[textsecure] Websocket sending message")
			if err := c.write(websocket.BinaryMessage, message); err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("[textsecure] Failed to send websocket message")
				return
			}
		case <-ticker.C:
			log.Debugf("[textsecure] Sending websocket ping message")
			if err := c.write(websocket.PingMessage, nil); err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("[textsecure] Failed to send websocket ping message")
				return
			}
		}
	}
}

// StartListening connects to the server and handles incoming websocket messages.
func StartListening() error {
	var err error

	wsconn = &Conn{send: make(chan []byte, 256)}
	err = wsconn.connect(config.ConfigFile.Server+websocketPath, config.ConfigFile.UUID, registration.Registration.Password)
	if err != nil {
		log.Errorf(err.Error())
		return err
	}

	defer wsconn.ws.Close()

	// Can only have a single goroutine call write methods
	go wsconn.writeWorker()

	wsconn.ws.SetReadDeadline(time.Now().Add(pongWait))
	wsconn.ws.SetPongHandler(func(string) error {
		log.Debugf("[textsecure] Received websocket pong message")
		wsconn.ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, bmsg, err := wsconn.ws.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Debugf("[textsecure] Websocket UnexpectedCloseError: %s", err)
			}
			return err
		}

		wsm := &signalservice.WebSocketMessage{}
		err = proto.Unmarshal(bmsg, wsm)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("[textsecure] Failed to unmarshal websocket message")
			return err
		}

		m := wsm.GetRequest().GetBody()

		if len(m) > 0 {
			plaintext, err := decryptReceivedMessage(m)
			if err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("[textsecure] Failed to decrypt received message")
			} else {
				env, err := createEnvelope(plaintext)
				if err != nil {
					log.WithFields(log.Fields{
						"error": err,
					}).Error("[textsecure] Failed to create envelope")
				}
				err = handleReceivedMessage(env)
				if err != nil {
					log.Debugf("[textsecure] Failed to handle received message: %+v", env)
					log.WithFields(log.Fields{
						"error": err,
					}).Error("[textsecure] Failed to handle received message")
				}
			}
		} else {
			log.Debugln("[textsecure] Ask for new messages")
			if wsm.GetRequest().GetPath() == "/api/v1/queue/empty" {
				log.Println("[textsecure] No new messages")
			} else {
				log.WithFields(log.Fields{
					"source": wsm.GetRequest().GetId(),
				}).Warn("[textsecure] Zero byte message received. Ignoring")
			}

		}

		err = wsconn.sendAck(wsm.GetRequest().GetId())
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("[textsecure] Failed to send ack")
			return err
		}

	}

}

// ErrNotListening is returned when trying to stop listening when there's no
// valid listening connection set up
var ErrNotListening = errors.New("[textsecure] there is no listening connection to stop")

// StopListening disables the receiving of messages.
func StopListening() error {
	if wsconn == nil {
		return ErrNotListening
	}

	if wsconn.ws != nil {
		wsconn.ws.Close()
	}

	return nil
}
