你是资深安全工程师、Agent系统架构师、Python后端工程师。

生成一个完整可运行项目：

项目名：

EVA-Agent
(Exploit Verification Agent)

目标：

构建一个：

HTTP + Containerized Runtime + LLM Agent + SSH Verification

漏洞利用执行与验证平台。

注意：

该系统仅用于：

- Docker靶场
- 本地实验环境
- 授权安全研究

禁止生成任何攻击PoC。

系统职责不是发现漏洞。

而是：

在用户提供EXP后，

自动：

1 执行EXP
2 SSH验证目标状态
3 判断利用效果
4 输出报告

------------------------------------------------
一、系统整体架构
------------------------------------------------

架构：

HTTP API
↓
Task Manager
↓
LLM Agent Planner
↓
EXP Runtime Container
↓
Execute EXP
↓
SSH Verification Agent
↓
Evidence Builder
↓
Rule Engine
↓
Optional LLM Judge
↓
Report

采用：

Controller / Worker

模式。

------------------------------------------------
二、Runtime Container
------------------------------------------------

系统核心：

单个Docker镜像。

预置：

语言环境：

- Python3
- Java17
- Go
- GCC/G++
- Node.js

预置常见库：

Python：

- requests
- pwntools
- pyyaml
- paramiko
- httpx

Java：

- Maven

Go：

- 常见构建链

支持：

用户上传：

.py
.jar
.go
.c
.cpp
.sh

支持：

动态执行。

禁止：

privileged container。

限制：

resource limit。

使用：

Docker SDK。

------------------------------------------------
三、HTTP API
------------------------------------------------

使用：

FastAPI。

接口：

POST /submit

接受：

multipart/form-data

参数：

1 exploit_file

EXP文件。

2 execute_cmd

执行命令。

例如：

python exp.py
java -jar exp.jar

3 target_ip

4 target_port

5 verify_type

支持：

rce
info_leak
priv_esc
auth_bypass

6 ssh_info

支持：

user
password
key

返回：

task_id

实现：

GET /task/{id}

查询：

状态。

实现：

GET /result/{id}

获取：

结果。

------------------------------------------------
四、Task Manager
------------------------------------------------

异步任务。

支持：

queue。

状态：

pending
running
success
failed
timeout

超时：

默认：

300s。

------------------------------------------------
五、Execution Worker
------------------------------------------------

负责：

执行EXP。

实现：

SandboxExecutor。

流程：

创建临时目录
↓
保存EXP
↓
执行用户命令
↓
收集：

stdout
stderr
exitcode
duration

支持：

timeout。

记录：

完整日志。

------------------------------------------------
六、SSH Verification Agent
------------------------------------------------

核心。

通过：

asyncssh

连接目标。

能力：

run()

统一返回：

stdout
stderr
exitcode

验证：

EXP执行后：

目标是否变化。

支持：

--------------------------------
1 RCE
--------------------------------

验证：

- 进程
- 文件
- 网络
- side effect

例如：

touch /tmp/pwned

验证：

存在。

--------------------------------
2 Info Leak
--------------------------------

验证：

敏感文件/内容。

--------------------------------
3 PrivEsc
--------------------------------

验证：

whoami
id
sudo

检查：

uid变化。

--------------------------------
4 Auth Bypass
--------------------------------

支持：

HTTP验证。

通过：

httpx。

验证：

401/403

↓

200

以及：

response body。

------------------------------------------------
七、Evidence Builder
------------------------------------------------

关联：

EXP执行结果
+
SSH结果
+
HTTP验证

生成：

Evidence Summary JSON。

例如：

{
  "verify_type":"rce",
  "exp_exit":0,
  "ssh_checks":[...],
  "evidence":[...]
}

------------------------------------------------
八、Rule Engine
------------------------------------------------

Rule-first。

YAML规则。

支持：

AND
OR
NOT

支持：

weight。

关闭LLM：

仍可工作。

------------------------------------------------
九、LLM Agent
------------------------------------------------
重要：

LLM配置必须：

Runtime Configurable。

禁止：

修改模型配置后重新构建Docker镜像。

即：

LLM配置：

与镜像完全解耦。

必须支持：

Hot-swappable LLM Backend。

------------------------------------------------
配置方式
------------------------------------------------

使用：

env + yaml

组合。

优先级：

ENV
>
config.yaml

支持：

热更新。

修改配置：

无需重新build镜像。

仅：

重启服务。

------------------------------------------------
配置目录
------------------------------------------------

实现：

config/

包含：

llm.yaml

示例：

provider: openai
base_url: http://host.docker.internal:8000/v1
api_key: sk-xxxx
model: gpt-4.1
temperature: 0

------------------------------------------------
环境变量覆盖
------------------------------------------------

支持：

EVA_LLM_PROVIDER
EVA_LLM_BASE_URL
EVA_LLM_API_KEY
EVA_LLM_MODEL

例如：

docker run \
-e EVA_LLM_BASE_URL=http://host.docker.internal:8000/v1 \
-e EVA_LLM_MODEL=qwen3 \
...

即可：

切换模型。

无需：

重新build。

------------------------------------------------
支持Provider
------------------------------------------------

采用：

OpenAI-compatible abstraction。

支持：

- OpenAI
- Claude-compatible gateway
- vLLM
- Ollama
- LM Studio
- OneAPI/OpenRouter
- Local Gateway

通过：

base_url + model

切换。

避免：

Provider耦合。

------------------------------------------------
LLM Client设计
------------------------------------------------

实现：

LLMClientFactory。

自动：

根据配置创建client。

例如：

OpenAIClient
CompatibleClient
OllamaClient

统一接口：

judge()

返回：

success
confidence
reasoning

------------------------------------------------
Docker部署要求
------------------------------------------------

docker-compose：

支持：

.env

配置。

示例：

services:
  eva:
    env_file:
      - .env

修改：

.env

无需：

重新构建镜像。

------------------------------------------------
安全要求
------------------------------------------------

API Key：

禁止：

硬编码。

必须：

ENV注入。

禁止：

进入镜像层。

禁止：

写死代码。

------------------------------------------------
README要求
------------------------------------------------

提供：

切换LLM：

示例。

包括：

OpenAI
vLLM
Ollama

演示。
------------------------------------------------
十、Report
------------------------------------------------

输出：

JSON
Markdown

包含：

EXP执行结果
SSH验证结果
规则得分
LLM判断

最终：

SUCCESS/FAIL。

------------------------------------------------
十一、Docker部署
------------------------------------------------

生成：

Dockerfile
docker-compose

单容器部署。

启动：

docker compose up

即可运行。

------------------------------------------------
十二、安全边界
------------------------------------------------

明确：

仅：

授权环境。

禁止：

生成：

攻击payload。

只实现：

执行框架。

------------------------------------------------
十三、代码要求
------------------------------------------------

要求：

- 完整代码
- 模块化
- 类型注解
- pytest
- README
- OpenAPI docs

先输出：

完整系统设计。

然后：

逐模块编码。

不要省略代码。
