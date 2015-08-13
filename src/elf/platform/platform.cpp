#include <elf/elf.h>
#include <elf/config.h>
#include <elf/net/http.h>
#include <elf/md5.h>
#include <elf/json.h>
#include <elf/time.h>
#include <elf/log.h>
#include <elf/pc.h>
#include <elf/platform/platform.h>
#include <cJSON/cJSON.h>
#include <fstream>
#include <string>
#include <map>
#include <deque>

namespace elf {

enum plat_req_type {
    PLAT_REQ_JSON,
};

struct plat_base_req {
    int plat_type;
    int type;
    std::string content;
    void *args;
    cJSON *resp;
    auth_cb cb;

    plat_base_req() : type(0), args(NULL), cb(NULL) {}
    virtual ~plat_base_req() {}

    plat_base_req(int _type, auth_cb _cb, void *_args)
    : type(_type)
    , args(_args)
    , cb(_cb) {}
    virtual bool push_resp(void *ptr, size_t size) = 0;
};

struct plat_base_resp {
    int code;
    std::string  username;
    std::string userid;
    std::string channel;
    std::string token;
    auth_cb cb;
    void *args;
};

struct plat_json_req : public plat_base_req {
    plat_json_req() : plat_base_req(PLAT_REQ_JSON, NULL, NULL) {}
    plat_json_req(auth_cb cb, void *args) : plat_base_req(PLAT_REQ_JSON, cb, args) {}
    virtual ~plat_json_req() {}

    bool push_resp(void *ptr, size_t size) {
        content.append((char*)ptr, size);
        resp = cJSON_Parse(content.c_str());
        if (resp == NULL) {
            return false;
        }
        return true;
    }
};

static cJSON* s_json;
static xqueue<plat_base_resp*> s_resps;
static void platform_on_auth(const plat_base_req *req);

int platform_init()
{
    s_json = NULL;
    return 0;
}

int platform_fini()
{
    if (s_json != NULL) {
        cJSON_Delete(s_json);
    }
    return 0;
}

int platform_load(const char *proto)
{
    assert(proto);

    std::fstream fs(proto, std::ios::in | std::ios::binary);

    if (!fs) {
        LOG_ERROR("json",
                "Can NOT open file %s.", proto);
        return -1;
    }

    std::stringstream iss;

    iss << fs.rdbuf();
    s_json = cJSON_Parse(iss.str().c_str());
    if (s_json == NULL) {
        LOG_ERROR("json",
                "Can NOT parse json file %s.", proto);
        return -1;
    }
    return 0;
}

static cJSON* platform_get_json()
{
    return s_json;
}

size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t realsize = size * nmemb;
    plat_base_req *base_req = static_cast<plat_base_req*>(userdata);
    if (base_req == NULL) {
        return 0;
    }

    LOG_DEBUG("net", "on cb userdata: %p", base_req->args);

    if (ptr == NULL || realsize == 0) {
        plat_base_resp *resp = E_NEW plat_base_resp;
        resp->code = PLATFORM_RESPONSE_FAILED;
        resp->cb = base_req->cb;
        resp->args = base_req->args;

        E_DELETE base_req;

        // push resp
        s_resps.push(resp);
        return realsize;
    }

    if (base_req->push_resp(ptr, realsize)) {
        platform_on_auth(base_req);
        cJSON_Delete(base_req->resp);
        E_DELETE base_req;
    }
    return realsize;
}

static void platform_on_auth(const plat_base_req *req)
{
    cJSON *success = cJSON_GetObjectItem(req->resp, "success");
    cJSON *info = cJSON_GetObjectItem(req->resp, "info");

    cJSON *code = cJSON_GetObjectItem(info, "code");
    cJSON *username = cJSON_GetObjectItem(info, "username");
    cJSON *userid = cJSON_GetObjectItem(info, "userid");
    cJSON *channel = cJSON_GetObjectItem(info, "channel");
    cJSON *token = cJSON_GetObjectItem(info, "token");

    LOG_INFO("platform",
            "onAuth(): success(%d), code(%d),\
            username(%s), userid(%d), channel(%s), token(%s)",
            success->valueint, code->valueint, username->valuestring,
            channel->valuestring, token->valuestring);

    plat_base_resp *resp = E_NEW plat_base_resp;

    if (success->valueint == 1) {
        resp->code = PLATFORM_OK;
    } else {
        resp->code = PLATFORM_USER_NOT_LOGININ;
    }
    resp->username = std::string(username->valuestring);
    resp->userid = std::string(userid->valuestring);
    resp->channel = std::string(channel->valuestring);
    resp->token = std::string(token->valuestring);
    resp->cb = req->cb;
    resp->args = req->args;

    // push resp
    s_resps.push(resp);
}

int platform_auth(const char *token, auth_cb cb, void *args) {
    LOG_DEBUG("net", "token: %s, platform_auth: %p", token, args);

    cJSON *setting = platform_get_json();
    if (setting == NULL) {
        return PLATFORM_SETTING_ERROR;
    }
    
    cJSON *url = cJSON_GetObjectItem(setting, "URL");
    if (url == NULL) {
        return PLATFORM_SETTING_ERROR;
    }

    std::string post_url;
    post_url.append(url->valuestring);

    std::string params;
    params.append("token=");
    params.append(token);

    // do post request
    plat_json_req *json_req = E_NEW plat_json_req(cb, args);
    http_json(post_url.c_str(), params.c_str(), write_callback, json_req);

    LOG_DEBUG("net", "auth url: %s", url->valuestring);
    return PLATFORM_OK;
}

int platform_proc() {
    std::deque<plat_base_resp*>::iterator itr;
    std::deque<plat_base_resp*> resps;

    s_resps.swap(resps);
    for (itr = resps.begin();itr != resps.end(); ++itr) {
        plat_base_resp *resp = *itr;
        if (resp->cb != NULL) {
            resp->cb(resp->code, resp->userid, resp->username,
                    resp->channel, resp->token, resp->args);
        }
        E_DELETE resp;
    }
    return 0;
}

} // namespace elf
