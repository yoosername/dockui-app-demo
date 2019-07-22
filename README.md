# dockui-app-demo

> Example App for use with [DockUI](https://github.com/yoosername/dockui)

## Quick start (Docker)

### Build Local Development Image

```shell
$ git clone https://github.com/yoosername/dockui-app-demo.git
$ cd dockui-app-demo
$ npm install
$ docker build --tag dockui/app-demo .
```

### Start the App

```shell
$ docker run -it \
  --env HTTP_PORT=3333 \
  --env HTTP_SCHEME=http \
  -p 3333:3333 \
  -v $(pwd):/app \
  dockui/app-demo
```
