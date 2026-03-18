//go:generate go run -mod=mod github.com/google/wire/cmd/wire
//go:build !wireinject

package main

import (
	"context"
)

func main() {
	app, err := createApp()
	if err != nil {
		panic(err)
	}
	if err := app.MQConsumer.StartConsumerHandlers(context.Background()); err != nil {
		panic(err)
	}
	if err := app.MQConsumer.Close(); err != nil {
		panic(err)
	}
}
