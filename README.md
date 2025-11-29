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


 ## TODO

 1. 开放搜索功能支持 url 传入参数，需要支持： 1. 左侧边栏支持默认隐藏；2. 顶部导航栏支持隐藏；3. agent或者chat 的id；4. 问题内容