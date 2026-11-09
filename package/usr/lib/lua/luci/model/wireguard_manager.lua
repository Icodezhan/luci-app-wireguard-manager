local uci = require "uci"
local ip = require "luci.ip"
local nixio = require "nixio"
local fs = require "nixio.fs"
local sys = require "luci.sys"
local ubus = require "ubus"
local json = require "luci.jsonc"

local M = {}
local network = "/etc/config/network"
local profile_dir = "/etc/wireguard-manager"
local handshake_cache = "/var/run/wireguard-manager-handshakes.json"
local active_window = 180
local client_fields = {
    Interface = { PrivateKey = true, Address = true, DNS = true, ListenPort = true, MTU = true },
    Peer = { PublicKey = true, PresharedKey = true, Endpoint = true, AllowedIPs = true,
        PersistentKeepalive = true }
}

local function check(ok, message)
    if not ok then error({ message = message }, 0) end
    return ok
end

local function trim(s)
    return (s or ""):match("^%s*(.-)%s*$")
end

local function list(value)
    if type(value) == "table" then return value end
    local result = {}
    for part in (value or ""):gmatch("[^,%s]+") do result[#result + 1] = part end
    return result
end

local function truth(value)
    return value == "1" or value == "yes" or value == "true" or value == "on" or value == "enabled"
end

local function quote(value)
    return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

local function run(...)
    local args = {}
    for i = 1, select("#", ...) do args[i] = quote(select(i, ...)) end
    return os.execute(table.concat(args, " ") .. " >/dev/null 2>&1") == 0
end

local function output(command)
    local stream = io.popen(command .. " 2>/dev/null", "r")
    if not stream then return "" end
    local result = stream:read("*a")
    stream:close()
    return result
end

local function wg_key(value)
    return value and #value == 44 and value:match("^[A-Za-z0-9+/]+[AEIMQUYcgkosw048]=$") and
        value ~= string.rep("A", 43) .. "="
end

local function pubkey(private)
    check(wg_key(private), "WireGuard 私钥无效。")
    local in_read, in_write = nixio.pipe()
    local out_read, out_write = nixio.pipe()
    local child = in_read and out_read and nixio.fork()
    if child == 0 then
        in_write:close()
        out_read:close()
        if nixio.dup(in_read, nixio.stdin) and nixio.dup(out_write, nixio.stdout) then
            in_read:close()
            out_write:close()
            nixio.exec("/usr/bin/wg", "pubkey")
        end
        os.exit(1)
    end
    if in_read then in_read:close() end
    if out_write then out_write:close() end
    if child then in_write:writeall(private .. "\n") end
    if in_write then in_write:close() end
    local result = child and trim(out_read:readall()) or ""
    if out_read then out_read:close() end
    if child then nixio.waitpid(child) end
    return check(wg_key(result) and result, "无法生成 WireGuard 公钥。")
end

local function generate()
    local key = trim(output("/usr/bin/wg genkey"))
    return check(wg_key(key) and key, "无法生成 WireGuard 私钥。")
end

local function cidr(value)
    if #value > 60 or not value:match("^[0-9A-Fa-f.:]+/?%d*$") then return nil end
    return ip.IPv4(value) or ip.IPv6(value)
end

local function addresses(value, label, only_hosts)
    local result, seen = {}, {}
    check(#list(value) <= 64, label .. "最多支持 64 项。")
    for _, raw in ipairs(list(value)) do
        local addr = check(cidr(raw), label .. "中包含无效的 IP 地址或网段。")
        local canonical = only_hosts and addr:host():string() or addr:string()
        check(not only_hosts or not raw:find("/", 1, true), label .. "需要填写 IP 地址。")
        if not seen[canonical] then
            result[#result + 1] = canonical
            seen[canonical] = true
        end
    end
    return result
end

local function integer(value, minimum, maximum, label)
    check(value:match("^%d+$") and tonumber(value) >= minimum and tonumber(value) <= maximum,
        label .. "必须是 " .. minimum .. "–" .. maximum .. " 之间的整数。")
    return tostring(tonumber(value))
end

local function endpoint(value)
    local host, port = value:match("^%[([a-fA-F0-9:.]+)%]:(%d+)$")
    if host then
        check(ip.IPv6(host), "Endpoint 的 IPv6 地址无效。")
    else
        host, port = value:match("^([A-Za-z0-9_.-]+):(%d+)$")
        check(host and #host <= 253 and host:match("^[A-Za-z0-9]") and not host:find("%.%."),
            "Endpoint 格式应为域名:端口、IPv4:端口或 [IPv6]:端口。")
    end
    return host, integer(port, 1, 65535, "Endpoint 端口")
end

local function format_endpoint(host, port)
    if not host or host == "" then return "" end
    return (host:find(":", 1, true) and "[" .. host .. "]" or host) .. ":" .. (port or "51820")
end

local function section(cursor, name)
    local cfg = name and name:match("^[A-Za-z0-9_]+$") and cursor:get_all("network", name)
    return check(cfg and cfg[".type"] == "interface" and cfg.proto == "wireguard" and cfg,
        "此 WireGuard 接口已不存在。")
end

local function peers(cursor, iface)
    local result = {}
    cursor:foreach("network", "wireguard_" .. iface, function(peer) result[#result + 1] = peer end)
    return result
end

local function peer_device(iface, status)
    return status and status.l3_device or iface
end

local function wg_show(device, field)
    return trim(output("/usr/bin/wg show " .. quote(device) .. " " .. quote(field)))
end

local function wg_exists(device)
    return run("/usr/bin/wg", "show", device, "public-key")
end

local function link_up(device)
    local link = ip.link(device)
    return link and link.up == true
end

local function data_by_key(raw, columns)
    local result = {}
    for line in raw:gmatch("[^\n]+") do
        local values = {}
        for value in line:gmatch("[^\t]+") do values[#values + 1] = value end
        if #values == columns + 1 then result[values[1]] = values end
    end
    return result
end

local function role(cfg, configured_peers)
    if cfg.wgm_role == "server" or cfg.wgm_role == "client" then return cfg.wgm_role end
    for _, peer in ipairs(configured_peers) do
        if peer.endpoint_host and peer.endpoint_host ~= "" then return "client" end
    end
    return "server"
end

local function needs_restart(peer)
    return truth(peer.route_allowed_ips) or not not wg_key(peer.preshared_key) or
        (peer.endpoint_host or "") ~= "" or (tonumber(peer.persistent_keepalive) or 0) > 0
end

local function status(bus, iface)
    if not bus then return nil end
    return bus:call("network.interface." .. iface, "status", {})
end

local function profile_path(iface, key)
    if not iface:match("^[A-Za-z0-9_]+$") or not wg_key(key) then return nil end
    local safe_key = key:sub(1, -2):gsub("%+", "-"):gsub("/", "_")
    return profile_dir .. "/" .. iface .. "." .. safe_key .. ".conf"
end

local function profile_exists(path)
    local file = path and fs.lstat(path)
    return file and file.type == "reg" and file.uid == 0 and file.modestr == "rw-------"
end

local function default_endpoint(cfg, port, lan)
    if cfg.wgm_endpoint then return cfg.wgm_endpoint end
    local address = lan and lan["ipv4-address"] and lan["ipv4-address"][1]
    return address and port and port > 0 and format_endpoint(address.address, port) or nil
end

local function write_private(path, bytes)
    local file = nixio.open(path, "w", "0600")
    if not file then return false end
    local written = file:writeall(bytes)
    local synced = file:sync()
    file:close()
    return written == #bytes and synced
end

local function record_handshakes(observed, now)
    local lock = nixio.open("/var/lock/wireguard-manager-handshakes.lock", "w", "0600")
    local locked = lock and lock:lock("tlock")
    local raw = fs.readfile(handshake_cache) or ""
    local previous = json.parse(raw)
    if type(previous) ~= "table" then previous = {} end
    local records = {}
    for id, peer in pairs(observed) do
        local record = previous[id]
        local prior = type(record) == "table" and tonumber(record.last) or 0
        local since
        if peer.recent then
            local start = type(record) == "table" and tonumber(record.since)
            since = peer.handshake
            if start and start <= prior and prior <= since and since - prior <= active_window then since = start end
            peer.connected_for = now - since
        elseif peer.handshake == 0 and prior <= now then
            peer.handshake = prior
        end
        if peer.handshake > 0 then
            peer.handshake_age = math.max(0, now - peer.handshake)
            records[id] = { last = peer.handshake, since = since }
        end
    end
    if locked then
        local bytes = json.stringify(records)
        if bytes ~= raw then
            local temp = handshake_cache .. ".tmp"
            if not (write_private(temp, bytes) and fs.rename(temp, handshake_cache)) then fs.unlink(temp) end
        end
    end
    if lock then lock:close() end
end

local function client_options(cfg, peer)
    return {
        address = table.concat(list(cfg.addresses), ", "), dns = table.concat(list(cfg.dns), ", "),
        mtu = cfg.mtu, listen_port = cfg.listen_port, public_key = peer.public_key,
        endpoint = format_endpoint(peer.endpoint_host, peer.endpoint_port),
        allowed_ips = table.concat(list(peer.allowed_ips), ", "),
        keepalive = peer.persistent_keepalive, routed = truth(peer.route_allowed_ips)
    }
end

function M.snapshot()
    local cursor, bus = uci.cursor(), ubus.connect()
    local result, observed = {}, {}
    local now = os.time()
    local lan = status(bus, "lan")
    cursor:foreach("network", "interface", function(cfg)
        if cfg.proto ~= "wireguard" then return end
        local iface = cfg[".name"]
        local st = status(bus, iface)
        local device = peer_device(iface, st)
        local up = st and st.up == true and link_up(device) or false
        local public = wg_show(device, "public-key")
        if not wg_key(public) and wg_key(cfg.private_key) then
            local ok, derived = pcall(pubkey, cfg.private_key)
            if ok then public = derived end
        end
        local configured_peers = peers(cursor, iface)
        local mode = role(cfg, configured_peers)
        local entries, known = {}, {}
        local handshake = data_by_key(wg_show(device, "latest-handshakes"), 1)
        local transfer = data_by_key(wg_show(device, "transfer"), 2)
        local endpoints = data_by_key(wg_show(device, "endpoints"), 1)
        local allowed = data_by_key(wg_show(device, "allowed-ips"), 1)
        local function display(peer)
            local key = peer.public_key or ""
            local last = handshake[key] and tonumber(handshake[key][2]) or 0
            local age = now - last
            local disabled = truth(peer.disabled)
            local entry = {
                id = peer[".name"], label = peer.description or key,
                exportable = mode == "server" and peer[".name"] ~= nil and
                    profile_exists(profile_path(iface, key)) or false,
                addresses = table.concat(list(peer.allowed_ips), ", "),
                endpoint = endpoints[key] and endpoints[key][2] ~= "(none)" and endpoints[key][2]
                    or format_endpoint(peer.endpoint_host, peer.endpoint_port),
                disabled = disabled, restarts = needs_restart(peer), handshake = last,
                recent = up and not disabled and last > 0 and age >= 0 and age <= active_window,
                rx = transfer[key] and transfer[key][2], tx = transfer[key] and transfer[key][3]
            }
            entries[#entries + 1] = entry
            if wg_key(key) then observed[iface .. ":" .. key] = entry end
            known[key] = true
        end
        for _, peer in ipairs(configured_peers) do display(peer) end
        for key, values in pairs(allowed) do
            if not known[key] then display({ public_key = key, allowed_ips = values[2] }) end
        end
        local port = tonumber(cfg.listen_port) or tonumber(wg_show(device, "listen-port"))
        local defaults = mode == "server" and {
            endpoint = cfg.wgm_endpoint, effective_endpoint = default_endpoint(cfg, port, lan),
            allowed_ips = table.concat(list(cfg.wgm_allowed_ips), ", "),
            dns = table.concat(list(cfg.wgm_dns), ", "),
            keepalive = cfg.wgm_keepalive or "25", retain = cfg.wgm_retain ~= "0"
        } or nil
        local editable
        if mode == "client" and #configured_peers == 1 then
            editable = client_options(cfg, configured_peers[1])
        end
        result[#result + 1] = {
            name = iface, role = mode, managed = cfg.wgm_role == mode, peers = entries, editable = editable,
            defaults = defaults, display_name = cfg.wgm_label,
            addresses = table.concat(list(cfg.addresses), ", "), public_key = wg_key(public) and public or nil,
            up = up, pending = st and st.pending == true or false,
            listen_port = port,
            autostart = cfg.auto ~= "0"
        }
    end)
    if bus then bus:close() end
    record_handshakes(observed, now)
    table.sort(result, function(a, b) return a.name < b.name end)
    return { interfaces = result }
end

local function with_lock(callback)
    local lock = check(nixio.open("/var/lock/wireguard-manager.lock", "w", "0600"), "无法打开配置锁。")
    local locked = lock:lock("tlock")
    local ok, result
    if locked then ok, result = pcall(callback) end
    lock:close()
    check(locked, "有另一个 WireGuard 操作正在执行，请稍后重试。")
    if not ok then error(result, 0) end
    return result
end

local function save_profile(path, conf)
    local dir = fs.lstat(profile_dir)
    if not dir then
        check(fs.mkdir(profile_dir, "0700"), "无法创建客户端配置目录。")
        dir = fs.lstat(profile_dir)
    end
    check(dir and dir.type == "dir" and dir.uid == 0 and dir.modestr == "rwx------",
        "客户端配置目录权限不正确。")
    local temp = path .. "." .. sys.uniqueid(12)
    if write_private(temp, conf) and fs.rename(temp, path) then return end
    fs.unlink(temp)
    check(false, "无法保存扫码配置。")
end

local function remove_profile(path)
    if path and fs.lstat(path) then
        check(fs.unlink(path), "已删除客户端，但保存的扫码配置清理失败。")
    end
end

local function transaction(change, apply, repair)
    check(trim(output("/sbin/uci -q changes network")) == "", "网络配置有未提交的更改，请先在 LuCI 保存或撤销。")
    local base = check(fs.readfile(network), "无法读取网络配置。")
    local dir = "/etc/.wgm-" .. sys.uniqueid(12)
    check(fs.mkdir(dir, "0700"), "无法创建配置事务目录。")
    local published
    local ok, result = pcall(function()
        check(fs.mkdir(dir .. "/delta", "0700") and write_private(dir .. "/network", base), "无法暂存网络配置。")
        local cursor = uci.cursor(dir, dir .. "/delta")
        check(cursor:load("network"), "无法加载暂存网络配置。")
        local response = change(cursor)
        check(cursor:commit("network"), "无法提交 WireGuard 配置。")
        local staged = check(fs.readfile(dir .. "/network"), "无法读取更新后的网络配置。")
        check(fs.readfile(network) == base and trim(output("/sbin/uci -q changes network")) == "",
            "网络配置在操作期间发生变化，请刷新后重试。")
        if staged ~= base then
            check(fs.rename(dir .. "/network", network), "无法写入网络配置。")
            published = staged
        end
        apply()
        return response
    end)
    if not ok and published then
        local restored = fs.readfile(network) == published and write_private(dir .. "/original", base) and
            fs.rename(dir .. "/original", network)
        local repaired
        if restored then repaired = pcall(repair) end
        if not restored or not repaired then
            result = { message = restored and "网络配置已恢复，但接口运行状态恢复失败，请在 LuCI 检查接口。" or
                "运行状态更新失败，网络配置无法自动恢复，请在 LuCI 检查接口。" }
        end
    end
    fs.unlink(dir .. "/network")
    fs.unlink(dir .. "/original")
    fs.unlink(dir .. "/delta/network")
    fs.rmdir(dir .. "/delta")
    fs.rmdir(dir)
    if not ok then error(result, 0) end
    return result
end

local function uci_set(cursor, iface, key, value)
    if value == nil or value == "" or (type(value) == "table" and #value == 0) then
        if cursor:get("network", iface, key) ~= nil then
            check(cursor:delete("network", iface, key), "无法清除网络参数。")
        end
    else
        check(cursor:set("network", iface, key, value), "无法保存网络参数。")
    end
end

local function uci_create(cursor, kind, name)
    if name then
        check(cursor:set("network", name, kind), "无法创建网络配置段。")
        return name
    end
    return check(cursor:add("network", kind), "无法创建网络配置段。")
end

local function scoped(iface, up)
    local bus = check(ubus.connect(), "无法连接到 netifd。")
    local function wait_for(want_up)
        for attempt = 1, 24 do
            local st = status(bus, iface)
            if st and not st.pending and (st.up == true) == want_up then
                local device = peer_device(iface, st)
                if not want_up or (link_up(device) and wg_key(wg_show(device, "public-key"))) then return true end
            end
            nixio.nanosleep(0, 200000000)
        end
    end
    local ok, result = pcall(function()
        check(status(bus, iface), "netifd 中找不到此接口。")
        local _, failure = bus:call("network.interface." .. iface, up and "up" or "down", {})
        check(not failure, "netifd 拒绝了接口启停请求。")
        return wait_for(up)
    end)
    bus:close()
    if not ok then error(result, 0) end
    check(result, up and "接口未能启动，请检查 Endpoint、路由及系统日志。" or "接口未能停止。")
end

local function reload()
    check(run("/bin/ubus", "call", "network", "reload"), "netifd 无法重新读取网络配置。")
end

local function server_ranges(configured)
    local pools = {}
    for _, raw in ipairs(list(configured)) do
        local addr = cidr(raw)
        if addr then
            local max = addr:is4() and 31 or 127
            local family = addr:is4() and 4 or 6
            if addr:prefix() > 0 and addr:prefix() <= max and not pools[family] then
                pools[family] = addr
            end
        end
    end
    return pools
end

local function reserved_ranges(cursor, iface, device, exclude_key)
    local reserved = {}
    local function reserve(value, host)
        for _, raw in ipairs(list(value)) do
            local addr = cidr(raw)
            if addr then reserved[#reserved + 1] = host and addr:host() or addr:network() end
        end
    end
    cursor:foreach("network", "interface", function(other)
        reserve(other.addresses, true)
        reserve(other.ipaddr, true)
    end)
    for _, peer in ipairs(peers(cursor, iface)) do
        if not exclude_key or peer.public_key ~= exclude_key then reserve(peer.allowed_ips) end
    end
    for key, values in pairs(data_by_key(wg_show(device, "allowed-ips"), 1)) do
        if key ~= exclude_key then reserve(values[2]) end
    end
    return reserved
end

local function allocate(cursor, iface, device, cfg)
    local reserved = reserved_ranges(cursor, iface, device)
    local pools, result = server_ranges(cfg.addresses), {}
    for _, family in ipairs({ 4, 6 }) do
        local pool = pools[family]
        if pool then
            local first = pool:network()
            local point_to_point = pool:prefix() == (family == 4 and 31 or 127)
            local candidate = point_to_point and first or first:add(1)
            local last = point_to_point and family == 4 and pool:broadcast() or pool:maxhost()
            local exhausted = true
            for _ = 1, #reserved + 1 do
                if not candidate or not pool:contains(candidate) or last:lower(candidate) then break end
                local conflict
                for _, used in ipairs(reserved) do
                    if used:is4() == candidate:is4() and used:contains(candidate) then
                        conflict = used
                        break
                    end
                end
                if not conflict then
                    result[#result + 1] = candidate:host():string() .. (family == 4 and "/32" or "/128")
                    exhausted = false
                    break
                end
                local high = family == 4 and conflict:broadcast() or conflict:maxhost()
                candidate = (high or conflict):add(1)
                if candidate and candidate:lower(first) then break end
            end
            check(not exhausted, "IPv" .. family .. " 地址池没有可用地址。")
        end
    end
    return check(#result > 0 and result, "服务端接口需要至少一个包含可分配地址的 IPv4 或 IPv6 网段。")
end

local function current(iface)
    local bus = check(ubus.connect(), "无法连接到 netifd。")
    local st = status(bus, iface)
    bus:close()
    return st or {}
end

local function label(value)
    value = trim(value)
    check(#value > 0 and #value <= 96 and not value:find("%c"), "名称需要填写，且长度不能超过 96 字节。")
    return value
end

local function client_addresses(allowed_ips)
    local result = {}
    for _, raw in ipairs(list(allowed_ips)) do
        local addr = cidr(raw)
        if addr then
            local bits = addr:is4() and 32 or 128
            if addr:prefix() == bits then result[#result + 1] = addr:host():string() .. "/" .. bits end
        end
    end
    return result
end

local function client_config(cfg, device, peer, private, assigned, overrides)
    overrides = overrides or {}
    local target = overrides.endpoint or default_endpoint(cfg,
        tonumber(cfg.listen_port) or tonumber(wg_show(device, "listen-port")), current("lan"))
    check(target, "请先在服务端设置中填写客户端可访问的 Endpoint。")
    local host, port = endpoint(trim(target))
    local remote_routes = addresses(overrides.allowed_ips or cfg.wgm_allowed_ips, "客户端 AllowedIPs")
    local dns = addresses(overrides.dns or cfg.wgm_dns, "客户端 DNS", true)
    local interval = trim(overrides.keepalive or cfg.wgm_keepalive)
    local keepalive = integer(interval ~= "" and interval or "25", 0, 65535, "保活间隔")
    if #remote_routes == 0 then
        local pools = server_ranges(cfg.addresses)
        for _, family in ipairs({ 4, 6 }) do
            local pool = pools[family]
            if pool then remote_routes[#remote_routes + 1] = pool:network():string() .. "/" .. pool:prefix() end
        end
    end
    check(#assigned > 0, "请先在客户端设置中填写至少一个 IPv4 或 IPv6 地址。")
    local server_key = wg_show(device, "public-key")
    if not wg_key(server_key) then server_key = pubkey(cfg.private_key) end
    local conf = { "[Interface]", "PrivateKey = " .. private, "Address = " .. table.concat(assigned, ", ") }
    if #dns > 0 then conf[#conf + 1] = "DNS = " .. table.concat(dns, ", ") end
    conf[#conf + 1] = "\n[Peer]"
    conf[#conf + 1] = "PublicKey = " .. server_key
    if peer and wg_key(peer.preshared_key) then conf[#conf + 1] = "PresharedKey = " .. peer.preshared_key end
    conf[#conf + 1] = "Endpoint = " .. format_endpoint(host, port)
    conf[#conf + 1] = "AllowedIPs = " .. table.concat(remote_routes, ", ")
    conf[#conf + 1] = "PersistentKeepalive = " .. keepalive
    local config = table.concat(conf, "\n") .. "\n"
    return check(#config <= 2331 and config, "客户端配置太长，无法生成二维码。请精简 AllowedIPs 或 DNS。")
end

local function add_peer(args)
    local iface, title = args.iface, label(args.label)
    local device, key, assigned, applied, profile, config
    return transaction(function(cursor)
        local cfg = section(cursor, iface)
        check(role(cfg, peers(cursor, iface)) == "server", "请选择服务端接口。")
        local st = current(iface)
        check(not st.pending, "接口正在切换状态，请稍后重试。")
        device = peer_device(iface, st)
        assigned = allocate(cursor, iface, device, cfg)
        local private = generate()
        key = pubkey(private)
        config = client_config(cfg, device, nil, private, assigned, args)
        local id = uci_create(cursor, "wireguard_" .. iface)
        uci_set(cursor, id, "description", title)
        uci_set(cursor, id, "public_key", key)
        uci_set(cursor, id, "allowed_ips", assigned)
        uci_set(cursor, id, "route_allowed_ips", "0")
        profile = cfg.wgm_retain ~= "0" and profile_path(iface, key) or nil
        return { config = config, addresses = assigned, label = title, retained = profile ~= nil }
    end, function()
        if wg_exists(device) then
            applied = true
            check(run("/usr/bin/wg", "set", device, "peer", key, "allowed-ips", table.concat(assigned, ",")),
                "无法向正在运行的接口添加客户端。")
        end
        if profile then save_profile(profile, config) end
    end, function()
        if applied and wg_exists(device) then
            check(run("/usr/bin/wg", "set", device, "peer", key, "remove"), "无法撤销运行中的客户端。")
        end
    end)
end

local function server_peer(cursor, iface, id)
    local peer = check(id and id:match("^[A-Za-z0-9_]+$") and cursor:get_all("network", id), "此客户端已不存在。")
    return check(peer[".type"] == "wireguard_" .. iface and wg_key(peer.public_key) and peer,
        "客户端与接口不匹配。")
end

local function server_defaults(args)
    local target = trim(args.endpoint)
    if target ~= "" then
        local host, port = endpoint(target)
        target = format_endpoint(host, port)
    end
    local routes = addresses(args.allowed_ips, "客户端 AllowedIPs")
    local dns = addresses(args.dns, "客户端 DNS", true)
    local keepalive = integer(trim(args.keepalive), 0, 65535, "保活间隔")
    return transaction(function(cursor)
        local cfg = section(cursor, args.iface)
        check(role(cfg, peers(cursor, args.iface)) == "server", "请选择服务端接口。")
        uci_set(cursor, args.iface, "wgm_endpoint", target)
        uci_set(cursor, args.iface, "wgm_allowed_ips", routes)
        uci_set(cursor, args.iface, "wgm_dns", dns)
        uci_set(cursor, args.iface, "wgm_keepalive", keepalive)
        uci_set(cursor, args.iface, "wgm_retain", args.retain == "1" and "1" or "0")
        return {}
    end, function() end, function() end)
end

local function edited_addresses(cursor, iface, device, cfg, peer, value)
    local function with_prefixes(raw, field)
        local result = addresses(raw, field)
        for index, entry in ipairs(result) do
            if not entry:find("/", 1, true) then
                result[index] = entry .. "/" .. cidr(entry):prefix()
            end
        end
        return result
    end
    local allowed = with_prefixes(value, "客户端 IP 或网段")
    check(#allowed > 0, "请填写至少一个客户端 IP 或网段。")
    local original = with_prefixes(peer.allowed_ips, "原有客户端 IP 或网段")
    if table.concat(allowed, ",") == table.concat(original, ",") then return nil end
    if profile_exists(profile_path(iface, peer.public_key)) then
        check(#client_addresses(allowed) > 0, "可扫码的客户端至少需要一个 IPv4 或 IPv6 地址。")
    end
    local reserved = reserved_ranges(cursor, iface, device, peer.public_key)
    local unchanged = {}
    for _, raw in ipairs(original) do unchanged[raw] = true end
    for _, raw in ipairs(allowed) do
        if not unchanged[raw] then
            local addr = cidr(raw)
            for _, other in ipairs(reserved) do
                check(other:is4() ~= addr:is4() or
                    (not other:contains(addr:host()) and not addr:contains(other:host())),
                    "地址与路由器或其他客户端冲突：" .. raw)
            end
            if addr:is4() and addr:prefix() == 32 then
                for _, local_address in ipairs(list(cfg.addresses)) do
                    local pool = cidr(local_address)
                    if pool and pool:is4() and pool:prefix() < 31 and pool:contains(addr) then
                        check(not pool:network():host():equal(addr:host()) and
                            not pool:broadcast():host():equal(addr:host()),
                            "请勿使用服务端网段的网络地址或广播地址。")
                    end
                end
            end
        end
    end
    return allowed
end

local function peer_change(args, action)
    local iface, previous, device, was_up, reload_needed, edited, routed_edit
    local live_edit = false
    local result = transaction(function(cursor)
        local cfg = section(cursor, args.iface)
        iface = cfg[".name"]
        local all = peers(cursor, iface)
        check(role(cfg, all) == "server", "请选择服务端接口。")
        local peer = server_peer(cursor, iface, args.peer)
        for _, other in ipairs(all) do
            check(other[".name"] == args.peer or other.public_key ~= peer.public_key, "存在重复公钥，请先在接口设置中处理。")
        end
        local st = current(iface)
        check(not st.pending, "接口正在切换状态，请稍后重试。")
        previous, device, was_up = peer, peer_device(iface, st), st.up == true
        reload_needed = needs_restart(peer)
        routed_edit = truth(peer.route_allowed_ips) and was_up
        if action == "rename" or action == "edit_peer" then
            uci_set(cursor, args.peer, "description", label(args.label))
            if action == "edit_peer" then
                edited = edited_addresses(cursor, iface, device, cfg, peer, args.allowed_ips)
                if edited then uci_set(cursor, args.peer, "allowed_ips", edited) end
            end
        elseif action == "remove" then
            check(cursor:delete("network", args.peer), "无法删除客户端。")
        else
            uci_set(cursor, args.peer, "disabled", action == "disable" and "1" or "0")
        end
        return {}
    end, function()
        if action == "rename" then return end
        if action == "edit_peer" then
            if not edited or truth(previous.disabled) or not wg_exists(device) then return end
            live_edit = true
            if routed_edit then
                scoped(iface, false)
                scoped(iface, true)
            else
                check(run("/usr/bin/wg", "set", device, "peer", previous.public_key, "allowed-ips",
                    table.concat(edited, ",")), "无法更新运行中的客户端地址。")
            end
            return
        end
        if reload_needed and was_up then
            scoped(iface, false)
            scoped(iface, true)
        elseif wg_exists(device) then
            if action == "enable" then
                check(run("/usr/bin/wg", "set", device, "peer", previous.public_key, "allowed-ips",
                    table.concat(list(previous.allowed_ips), ",")), "无法启用客户端。")
            else
                check(run("/usr/bin/wg", "set", device, "peer", previous.public_key, "remove"), "无法移除运行中的客户端。")
            end
        end
    end, function()
        if action == "rename" then return end
        if action == "edit_peer" then
            if live_edit then
                if routed_edit then
                    scoped(iface, false)
                    scoped(iface, true)
                else
                    check(run("/usr/bin/wg", "set", device, "peer", previous.public_key, "allowed-ips",
                        table.concat(list(previous.allowed_ips), ",")), "无法恢复原有客户端地址。")
                end
            end
            return
        end
        if was_up then
            scoped(iface, false)
            scoped(iface, true)
        end
    end)
    if action == "remove" then remove_profile(profile_path(iface, previous.public_key)) end
    return result
end

local function parse_client(text)
    check(#text <= 8192, "配置文件不能超过 8 KB。")
    local config, group = {}, nil
    text = text:gsub("^\239\187\191", "")
    for raw in text:gmatch("[^\r\n]+") do
        local line = trim(raw:gsub("#.*$", ""))
        if line ~= "" then
            local section_name = line:match("^%[([A-Za-z]+)%]$")
            if section_name then
                check(client_fields[section_name] and not config[section_name],
                    "配置必须包含一个 [Interface] 和一个 [Peer]。")
                group = section_name
                config[group] = {}
            else
                local key, value = line:match("^([A-Za-z]+)%s*=%s*(.-)$")
                check(group and key and client_fields[group][key], "配置包含不支持的字段或格式。")
                if config[group][key] then
                    check(key == "Address" or key == "DNS" or key == "AllowedIPs", "配置中有重复字段。")
                    value = config[group][key] .. ", " .. value
                end
                config[group][key] = value
            end
        end
    end
    check(config.Interface and config.Peer, "配置必须包含 [Interface] 和 [Peer]。")
    return config.Interface, config.Peer
end

local function export_peer(args)
    local cursor = uci.cursor()
    local cfg = section(cursor, args.iface)
    check(role(cfg, peers(cursor, args.iface)) == "server", "请选择服务端接口。")
    local peer = server_peer(cursor, args.iface, args.peer)
    local path = profile_path(args.iface, peer.public_key)
    check(profile_exists(path), "此客户端的配置未保存。请新建客户端并扫描新二维码。")
    local stored = check(fs.readfile(path, 2332), "无法读取扫码配置。")
    check(#stored > 0 and #stored <= 2331, "保存的扫码配置无效。")
    local interface = parse_client(stored)
    local private = interface.PrivateKey
    check(wg_key(private) and pubkey(private) == peer.public_key, "保存的私钥与客户端公钥不匹配。")
    local assigned = client_addresses(peer.allowed_ips)
    local device = peer_device(args.iface, current(args.iface))
    return { config = client_config(cfg, device, peer, private, assigned), addresses = assigned,
        label = peer.description, retained = true }
end

local function same_client_options(args, old, peer)
    local saved = client_options(old, peer)
    if trim(args.conf) ~= "" or trim(args.private_key) ~= "" or trim(args.preshared_key) ~= "" or
        args.clear_psk == "1" or (args.route == "1") ~= saved.routed then return false end
    for _, field in ipairs({ "dns", "mtu", "listen_port", "public_key", "endpoint", "allowed_ips", "keepalive" }) do
        if trim(args[field]) ~= trim(saved[field]) then return false end
    end
    return trim(args.addresses) == saved.address
end

local function set_tunnel(args, action)
    local name = trim(args.iface)
    check(#name <= 15 and name:match("^[A-Za-z][A-Za-z0-9_]*$") and name ~= "all",
        "接口名需以字母开头，最多 15 个字符，只能包含字母、数字和下划线。")
    local st, was_up, original_exists, removed_peers, display_only
    local result = transaction(function(cursor)
        local editing = action == "edit_client"
        local removing = action == "delete_tunnel"
        local server = action == "create_server"
        local old, peer
        st = current(name)
        was_up = st.up == true
        check(not st.pending, "接口正在切换状态，请稍后重试。")
        if editing or removing then
            old = section(cursor, name)
            original_exists = true
            local entries = peers(cursor, name)
            if removing then
                check(old.wgm_role == "client" or old.wgm_role == "server", "只允许删除插件创建的接口。")
                for _, entry in ipairs(entries) do
                    check(cursor:delete("network", entry[".name"]), "无法删除接口的 Peer。")
                end
                removed_peers = entries
                check(cursor:delete("network", name), "无法删除接口。")
                return {}
            end
            check(role(old, entries) == "client" and #entries == 1,
                "仅支持编辑包含一个远端 Peer 的客户端接口。")
            peer = entries[1]
            if args.display_name ~= nil then
                local display_name = trim(args.display_name)
                uci_set(cursor, name, "wgm_label", display_name ~= "" and label(display_name) or nil)
                display_only = same_client_options(args, old, peer)
                if display_only then return {} end
            end
        else
            check(not cursor:get("network", name) and not st.proto and not fs.stat("/sys/class/net/" .. name)
                and #peers(cursor, name) == 0, "接口名已存在或有同名的残留 Peer 配置。")
            uci_create(cursor, "interface", name)
            uci_set(cursor, name, "proto", "wireguard")
            uci_set(cursor, name, "auto", "0")
            uci_set(cursor, name, "wgm_role", server and "server" or "client")
        end
        local intf, remote
        if trim(args.conf) ~= "" then
            intf, remote = parse_client(args.conf)
            check(wg_key(trim(intf.PrivateKey)), "导入的配置缺少有效的本机私钥。")
        else
            intf = { PrivateKey = args.private_key, Address = args.addresses, DNS = args.dns,
                ListenPort = args.listen_port, MTU = args.mtu }
            remote = { PublicKey = args.public_key, PresharedKey = args.preshared_key, Endpoint = args.endpoint,
                AllowedIPs = args.allowed_ips, PersistentKeepalive = args.keepalive }
        end
        local local_addresses = addresses(intf.Address, "接口地址")
        check(#local_addresses > 0, "请填写接口地址及前缀。")
        local private = trim(intf.PrivateKey)
        if private == "" then private = old and old.private_key or generate() end
        local public = pubkey(private)
        local port = trim(intf.ListenPort)
        local mtu = trim(intf.MTU)
        if port ~= "" then
            port = integer(port, 1, 65535, "监听端口")
            cursor:foreach("network", "interface", function(other)
                local other_name = other[".name"]
                if other_name == name or other.proto ~= "wireguard" then return end
                local actual = tonumber(wg_show(peer_device(other_name, current(other_name)), "listen-port"))
                check(tonumber(other.listen_port) ~= tonumber(port) and actual ~= tonumber(port),
                    "监听端口已被另一个 WireGuard 接口使用。")
            end)
        end
        if mtu ~= "" then mtu = integer(mtu, 576, 9000, "MTU") end
        if server then
            local pools = server_ranges(local_addresses)
            check(pools[4] or pools[6], "服务端至少需要一个可分配客户端地址的网段。")
            check(port ~= "", "请填写服务端监听端口。")
            cursor:foreach("network", "interface", function(other)
                local other_name = other[".name"]
                if other_name == name then return end
                for _, configured in ipairs(list(other.addresses)) do
                    local existing = cidr(configured)
                    if existing then
                        for _, raw in ipairs(local_addresses) do
                            local range = cidr(raw)
                            check(not existing:contains(range:host()) and not range:contains(existing:host()),
                                "服务端网段与另一个接口的配置重叠。")
                        end
                    end
                end
            end)
            for _, raw in ipairs(local_addresses) do
                local range = cidr(raw)
                for _, route in ipairs(ip.routes({ family = range:is4() and 4 or 6, table = 254 }) or {}) do
                    if route.dest and route.dest:prefix() > 0 and
                        (route.dest:contains(range:host()) or range:contains(route.dest:host())) then
                        check(false, "服务端网段与现有路由重叠，请选择独立网段。")
                    end
                end
            end
        else
            local host, ep_port = endpoint(trim(remote.Endpoint))
            local allowed = addresses(remote.AllowedIPs, "远端 AllowedIPs")
            check(#allowed > 0, "请至少填写一个远端 AllowedIPs 网段。")
            local key = trim(remote.PublicKey)
            check(wg_key(key) and key ~= public, "远端公钥无效或与本机公钥相同。")
            local psk = trim(remote.PresharedKey)
            if psk == "" and peer and trim(args.conf) == "" and args.clear_psk ~= "1" then psk = peer.preshared_key or "" end
            check(psk == "" or wg_key(psk), "预共享密钥无效。")
            local keepalive = trim(remote.PersistentKeepalive)
            if keepalive ~= "" then keepalive = integer(keepalive, 0, 65535, "保活间隔") end
            local id = peer and peer[".name"] or uci_create(cursor, "wireguard_" .. name)
            if not peer then uci_set(cursor, id, "description", "远端服务端") end
            uci_set(cursor, id, "endpoint_host", host)
            uci_set(cursor, id, "endpoint_port", ep_port)
            uci_set(cursor, id, "public_key", key)
            uci_set(cursor, id, "preshared_key", psk)
            uci_set(cursor, id, "allowed_ips", allowed)
            uci_set(cursor, id, "route_allowed_ips", args.route == "1" and "1" or "0")
            uci_set(cursor, id, "persistent_keepalive", keepalive)
        end
        uci_set(cursor, name, "private_key", private)
        uci_set(cursor, name, "addresses", local_addresses)
        uci_set(cursor, name, "listen_port", port)
        uci_set(cursor, name, "mtu", mtu)
        local dns = addresses(intf.DNS, "DNS", true)
        uci_set(cursor, name, "dns", dns)
        if not server and (not old or #dns > 0) then uci_set(cursor, name, "peerdns", "0") end
        return { public_key = public }
    end, function()
        if display_only then return end
        if was_up then scoped(name, false) end
        reload()
        if was_up and action ~= "delete_tunnel" then scoped(name, true) end
    end, function()
        if display_only then return end
        reload()
        if original_exists and was_up then scoped(name, true) end
    end)
    for _, peer in ipairs(removed_peers or {}) do remove_profile(profile_path(name, peer.public_key)) end
    return result
end

local function autostart(args)
    return transaction(function(cursor)
        section(cursor, args.iface)
        uci_set(cursor, args.iface, "auto", args.enabled == "1" and "1" or "0")
        return {}
    end, function() end, function() end)
end

function M.mutate(args)
    local action = args.action
    return with_lock(function()
        if action == "add_peer" then return add_peer(args) end
        if action == "export_peer" then return export_peer(args) end
        if action == "server_defaults" then return server_defaults(args) end
        if action == "enable" or action == "disable" or action == "remove" or action == "rename" or action == "edit_peer" then
            return peer_change(args, action)
        end
        if action == "create_server" or action == "create_client" or action == "edit_client" or action == "delete_tunnel" then
            return set_tunnel(args, action)
        end
        if action == "autostart" then return autostart(args) end
        if action == "start" or action == "stop" then
            section(uci.cursor(), args.iface)
            local start = action == "start"
            local previous = current(args.iface)
            check(not previous.pending, "接口正在切换状态，请稍后重试。")
            local ok, failure = pcall(scoped, args.iface, start)
            if not ok then
                if start and not previous.up then pcall(scoped, args.iface, false) end
                error(failure, 0)
            end
            return {}
        end
        check(false, "未知操作。")
    end)
end

return M
