/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/domaingts/ghproxy/pkg/cloudflare"
	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
)

var (
	address string
	tlsPath string
	auth    string
	cdn bool
)

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	PreRun: preRun,
	Run: func(cmd *cobra.Command, args []string) {
		run()
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
	startCmd.Flags().StringVarP(&address, "address", "a", "", "Listening port.")
	startCmd.Flags().StringVar(&tlsPath, "tls", "", "Certificate file path.")
	startCmd.Flags().StringVar(&auth, "auth", "", "Basic auth for http.")
	startCmd.Flags().BoolVarP(&cdn, "cdn", "c", false, "Use cloudflare cdn.")
}

var (
	logger *zap.Logger
	client *http.Client
)

func initLogger() {
	var err error
	logger, err = zap.NewDevelopment(zap.AddCaller())
	if err != nil {
		panic(err)
	}
}

func initClient() {
	client = &http.Client{
		Transport: &http2.Transport{},
		Timeout:   time.Minute,
	}
}

func preRun(cmd *cobra.Command, args []string) {
	initLogger()
	initClient()
	if address == "" {
		logger.Error("address is needed", zap.String("addr", address))
		os.Exit(0)
	}
	if auth != "" {
		cred := strings.Split(auth, ":")
		if len(cred) < 2 {
			logger.Error("error format auth", zap.String("auth", auth))
			os.Exit(0)
		}
	}
}

func run() {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.UseH2C = true
	if cdn {
		err := r.SetTrustedProxies(cloudflare.CloudflareIPs)
		if err != nil {
			logger.Error("failed to set trusted proxies", zap.Error(err))
			return
		}
	}
	if auth != "" {
		cred := strings.Split(auth, ":")
		r.Use(gin.BasicAuth(gin.Accounts{
			cred[0]: cred[1],
		}))
	}
	r.NoRoute(proxy)
	server := &http.Server{
		Addr:    address,
		Handler: r.Handler(),
	}
	logger.Info("start http server", zap.String("addr", address))
	var err error
	if tlsPath == "" {
		err = server.ListenAndServe()
	} else {
		certificate := path.Join(tlsPath, "server.pem")
		key := path.Join(tlsPath, "server.key")
		err = server.ListenAndServeTLS(certificate, key)
	}
	if err != nil {
		logger.Error("failed to start http server", zap.Error(err))
		return
	}
}

func proxy(c *gin.Context) {
	if c.Request.Method != "GET" {
		c.Status(http.StatusNotFound)
	}
	remoteAddress := "https://" + strings.TrimLeft(c.Request.RequestURI, "/")
	logger.Debug("get response from remoteAddress", zap.String("remoteAddress", remoteAddress))
	resp, err := client.Get(remoteAddress)
	if err != nil {
		logger.Error("failed to request", zap.String("url", remoteAddress), zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	for name, values := range resp.Header {
		for _, value := range values {
			c.Header(name, value)
		}
	}

	// Set status code
	c.Status(resp.StatusCode)

	// Stream the response body
	_, err = io.Copy(c.Writer, resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
}
