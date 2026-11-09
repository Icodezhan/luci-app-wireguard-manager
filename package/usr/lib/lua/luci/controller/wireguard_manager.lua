module("luci.controller.wireguard_manager", package.seeall)

function index()
    local page = entry({ "admin", "network", "wireguard_manager" },
        template("wireguard_manager/index"), "WireGuard 管理", 85)
    page.sysauth = "root"
    page.sysauth_authenticator = "htmlauth"
    page.dependent = true
    entry({ "admin", "network", "wireguard_manager", "api" }, post("api")).leaf = true
end

function api()
    local http = require "luci.http"
    local dispatcher = require "luci.dispatcher"
    local json = require "luci.jsonc"
    local function respond(status, reason, data)
        http.status(status, reason)
        http.header("Cache-Control", "no-store")
        http.header("X-Content-Type-Options", "nosniff")
        http.prepare_content("application/json")
        http.write(json.stringify(data))
    end
    if dispatcher.context.authuser ~= "root" then
        return respond(403, "Forbidden", { error = "此功能需要 root 登录。" })
    end
    local length = tonumber(http.getenv("CONTENT_LENGTH"))
    if not length or length < 1 or length > 40000 then
        return respond(413, "Payload Too Large", { error = "请求过大或缺少表单数据。" })
    end
    local manager = require "luci.model.wireguard_manager"
    local action = http.formvalue("action")
    local ok, result
    if action == "list" then
        ok, result = pcall(manager.snapshot)
    else
        local args = { action = action }
        for _, field in ipairs({ "iface", "peer", "label", "display_name", "endpoint", "allowed_ips", "dns", "keepalive",
            "listen_port", "mtu", "addresses", "conf", "private_key", "public_key", "preshared_key",
            "route", "clear_psk", "enabled", "retain" }) do
            args[field] = http.formvalue(field)
        end
        ok, result = pcall(manager.mutate, args)
    end
    if ok then return respond(200, "OK", result) end
    if type(result) == "table" and result.message then
        return respond(400, "Bad Request", { error = result.message })
    end
    return respond(500, "Internal Server Error", { error = "WireGuard 操作遇到内部错误。" })
end
