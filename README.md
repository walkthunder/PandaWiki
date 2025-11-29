## 启动部署 -  backend api 服务

./backend中的服务端代码发布，对应的docker image是 panda-wiki-api

 - 1. 本地打包构建，并传输到服务器，默认 root@8.140.221.27
```
./deploy/local-deploy.sh
```
>> 也默认会重新构建panda-wiki-consumer image

 - 2. 服务重启

 ```
 ./deploy/remote-deploy.sh
 ```

## 部署

### web/app

下面的 .env 文件中，注意本地直接启动的TARGET，跟docker compose 部署的TARGET的配置是不同的 Host:
- 本地开发建议直接用 localhost
- docker compose 的时候，用 panda-wiki-api


 ## TODO

 1. 开放搜索功能支持 url 传入参数，需要支持： 1. 左侧边栏支持默认隐藏；2. 顶部导航栏支持隐藏；3. agent或者chat 的id；4. 问题内容