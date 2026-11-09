/* global qrcodegen */
(function () {
    'use strict';

    const app = document.getElementById('wgm');
    const interfaces = document.getElementById('wgm-interfaces');
    const summary = document.getElementById('wgm-summary');
    const status = document.getElementById('wgm-status');
    const dialog = document.getElementById('wgm-dialog');
    let updating = false;
    let changing = false;

    function node(tag, value, className) {
        const el = document.createElement(tag);
        if (value != null) el.textContent = value;
        if (className) el.className = className;
        return el;
    }

    function button(title, click, style) {
        const el = node('button', title, 'cbi-button cbi-button-' + (style || 'action'));
        el.type = 'button';
        el.addEventListener('click', click);
        return el;
    }

    async function api(action, values) {
        const data = new URLSearchParams({ action, token: app.dataset.token });
        Object.entries(values || {}).forEach(([key, value]) => data.set(key, value));
        const response = await fetch(app.dataset.api, {
            method: 'POST', body: data, credentials: 'same-origin', cache: 'no-store'
        });
        if (!/application\/json/.test(response.headers.get('content-type') || '')) {
            throw new Error('请求未成功。请刷新页面并确认 LuCI 登录仍然有效。');
        }
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || '请求失败。');
        return result;
    }

    function message(text, error) {
        status.textContent = text;
        status.className = error ? 'wgm-error' : '';
    }

    function bytes(value) {
        if (value == null) return '—';
        let size = Number(value);
        const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
        let unit = 0;
        while (size >= 1024 && unit < units.length - 1) {
            size /= 1024;
            unit++;
        }
        return size.toFixed(unit ? 1 : 0) + ' ' + units[unit];
    }

    function duration(value) {
        if (value < 60) return value + ' 秒';
        if (value < 3600) return Math.floor(value / 60) + ' 分钟';
        if (value < 86400) return Math.floor(value / 3600) + ' 小时 ' + Math.floor(value % 3600 / 60) + ' 分钟';
        return Math.floor(value / 86400) + ' 天 ' + Math.floor(value % 86400 / 3600) + ' 小时';
    }

    async function refresh(showTime) {
        if (updating || changing) return;
        updating = true;
        try {
            const result = await api('list');
            const data = Array.isArray(result.interfaces) ? result.interfaces : [];
            const clients = data.filter(cfg => cfg.role === 'server').flatMap(cfg => cfg.peers || []);
            summary.replaceChildren(
                badge(data.filter(cfg => cfg.up).length + ' / ' + data.length + ' 隧道运行'),
                badge(clients.length + ' 个客户端'),
                badge(data.filter(cfg => cfg.role === 'server' && cfg.up)
                    .flatMap(cfg => cfg.peers || []).filter(peer => peer.recent && !peer.disabled).length + ' 个最近握手', 'live')
            );
            interfaces.replaceChildren(...data.map(renderInterface));
            if (showTime || !status.textContent || status.className) {
                message(data.length ? '已刷新 ' + new Date().toLocaleTimeString() : '尚无 WireGuard 接口。');
            }
        } catch (error) {
            message(error.message, true);
        } finally {
            updating = false;
        }
    }

    async function change(action, values, warning) {
        if (changing || (warning && !window.confirm(warning))) return;
        changing = true;
        try {
            await api(action, values);
            message('操作已完成。');
        } catch (error) {
            message(error.message, true);
            return;
        } finally {
            changing = false;
        }
        await refresh(false);
    }

    function badge(value, variant) {
        return node('span', value, 'wgm-badge' + (variant ? ' wgm-' + variant : ''));
    }

    function peerTool(title, path, click) {
        const control = node('button', null, 'wgm-peer-tool');
        control.type = 'button';
        control.title = title;
        control.setAttribute('aria-label', title);
        control.addEventListener('click', click);
        if (path) {
            const ns = 'http://www.w3.org/2000/svg';
            const icon = document.createElementNS(ns, 'svg');
            icon.setAttribute('viewBox', '0 0 24 24');
            icon.setAttribute('aria-hidden', 'true');
            const shape = document.createElementNS(ns, 'path');
            shape.setAttribute('d', path);
            icon.append(shape);
            control.append(icon);
        }
        return control;
    }

    function renderInterface(cfg) {
        const section = node('section', null, 'wgm-interface');
        const mode = cfg.role === 'server' ? '服务端' : '客户端';
        const header = node('div', null, 'wgm-interface-head');
        const identity = node('div');
        const title = node('div', null, 'wgm-inline');
        title.append(node('h3', cfg.display_name || cfg.name), badge(mode),
            badge(cfg.pending ? '切换中' : cfg.up ? '运行中' : '已停止', cfg.up ? 'live' : ''));
        identity.append(title, node('p', (cfg.addresses || '暂无接口地址') +
            (cfg.listen_port ? ' · UDP ' + cfg.listen_port : ''), 'wgm-muted'));
        if (cfg.defaults) identity.append(node('p', '客户端 Endpoint · ' +
            (cfg.defaults.effective_endpoint || '待设置'), 'wgm-muted'));
        const actions = node('div', null, 'wgm-actions');
        if (cfg.defaults) {
            const add = button('＋ 新建客户端', () => peerForm(cfg), 'add');
            add.classList.add('wgm-primary');
            actions.append(add, button('服务端设置', () => defaultsForm(cfg)));
        }
        if (cfg.editable) actions.append(button('编辑隧道', () => tunnelForm('edit_client', cfg)));
        const settings = node('details', null, 'wgm-interface-settings');
        settings.append(node('summary', '接口操作'));
        const extra = node('div', null, 'wgm-actions');
        const target = { iface: cfg.name };
        const toggle = button(cfg.up ? '停止' : '启动', () => change(cfg.up ? 'stop' : 'start', target,
            cfg.up ? '停止 ' + cfg.name + ' 会断开这个隧道。继续？' : null), cfg.up ? 'reset' : 'apply');
        toggle.disabled = cfg.pending;
        extra.append(toggle, button(cfg.autostart ? '改为手动启动' : '设为开机启动',
            () => change('autostart', { ...target, enabled: cfg.autostart ? '0' : '1' })));
        if (cfg.managed) extra.append(button('删除接口', () => change('delete_tunnel', target,
            '删除 ' + cfg.name + ' 及其所有 Peer？'), 'remove'));
        settings.append(extra);
        if (cfg.display_name) settings.append(node('p', '系统接口 ' + cfg.name, 'wgm-muted'));
        if (cfg.public_key) settings.append(node('p', '接口公钥 ' + cfg.public_key, 'wgm-muted'));
        header.append(identity, actions);
        section.append(header, settings);
        const peers = Array.isArray(cfg.peers) ? cfg.peers : [];
        if (!peers.length) {
            section.append(node('p', cfg.defaults ? '还没有客户端。点击「新建客户端」生成扫码配置。' : '暂无远端 Peer。', 'wgm-empty'));
            return section;
        }
        const cards = node('div', null, 'wgm-clients');
        cards.append(...peers.map(peer => renderPeer(cfg, peer)));
        section.append(cards);
        return section;
    }

    function renderPeer(cfg, peer) {
        const card = node('article', null, 'wgm-peer');
        const name = peer.label || '未命名';
        const info = node('div', null, 'wgm-peer-info');
        const title = node('div', null, 'wgm-inline');
        const active = cfg.up && peer.recent && !peer.disabled;
        const state = peer.disabled ? '已禁用' : !cfg.up ? '接口已停止' :
            active ? '最近握手' : peer.handshake ? '握手超时' : '等待连接';
        if (active) {
            const dot = node('span', null, 'wgm-activity');
            dot.setAttribute('aria-hidden', 'true');
            title.append(dot);
        }
        title.append(node('h4', name), badge(state, active ? 'live' : ''));
        const address = node('div', null, 'wgm-peer-address');
        address.append(node('span', peer.addresses || '—', 'wgm-addresses'));
        if (peer.handshake > 0) {
            const last = new Date(peer.handshake * 1000).toLocaleString();
            const when = peer.handshake_age == null ? last : duration(peer.handshake_age) + '前';
            const time = node('time', active && peer.connected_for != null ?
                '已连接约 ' + duration(peer.connected_for) : '上次握手 ' + when, 'wgm-muted');
            time.dateTime = new Date(peer.handshake * 1000).toISOString();
            time.title = '上次握手 ' + last;
            address.append(time);
        } else {
            address.append(node('span', '尚无握手', 'wgm-muted'));
        }
        info.append(title, address);
        if (peer.endpoint) info.append(node('p', peer.endpoint, 'wgm-muted'));
        const side = node('div', null, 'wgm-peer-side');
        side.append(node('p', '↓ ' + bytes(peer.rx) + '  ↑ ' + bytes(peer.tx), 'wgm-traffic'));
        if (cfg.role === 'server' && peer.id) {
            const args = { iface: cfg.name, peer: peer.id };
            const tools = node('div', null, 'wgm-peer-tools');
            if (!peer.exportable) {
                const help = node('details', null, 'wgm-profile-help');
                help.append(node('summary', '未保存扫码配置'),
                    node('p', '扫码需要包含客户端私钥的完整配置。可继续使用原来的配置，或新建客户端生成二维码。', 'wgm-muted'));
                info.append(help);
            }
            const notice = cfg.up && peer.restarts ? '此操作会短暂重启 ' + cfg.name + '。' : '';
            const toggle = peerTool(peer.disabled ? '启用客户端' : '禁用客户端', null,
                () => change(peer.disabled ? 'enable' : 'disable', args, notice ? notice + '继续？' : null));
            toggle.classList.add('wgm-peer-toggle');
            toggle.setAttribute('role', 'switch');
            toggle.setAttribute('aria-label', '启用客户端');
            toggle.setAttribute('aria-checked', String(!peer.disabled));
            const edit = peerTool('编辑客户端', 'M13 6l5 5M4 20l5-1L20 8l-4-4L5 15z',
                () => showForm('编辑客户端', 'edit_peer', args, [
                    { name: 'label', title: '名称', value: name, required: true, max: 96 },
                    { name: 'allowed_ips', title: '客户端 IP 或网段', value: peer.addresses, required: true },
                ], '多个地址用逗号分隔。使用服务端网段以外的地址时，需要相应路由。修改后请在设备上更新配置。'));
            const scan = peerTool('扫码', 'M3 3h6v6H3zM15 3h6v6h-6zM3 15h6v6H3zM15 15h2v2h-2zM21 15v6h-6M12 3v3m0 5v3M3 12h4m10 0h4m-9 7v2',
                () => exportPeer(args, true));
            const download = peerTool('下载 .conf', 'M12 3v12m-4-4 4 4 4-4M4 16v4h16v-4',
                () => exportPeer(args, false));
            scan.disabled = download.disabled = !peer.exportable;
            const remove = peerTool('删除客户端', 'M4 6h16M9 6V3h6v3m3 0-1 15H7L6 6m4 4v7m4-7v7',
                () => change('remove', args, notice + '确定删除 ' + name + '？'));
            remove.classList.add('wgm-peer-delete');
            tools.append(toggle, edit, scan, download, remove);
            side.append(tools);
        }
        card.append(info, side);
        return card;
    }

    function field(form, definition) {
        const label = node('label', null, 'wgm-field');
        const type = definition.type || 'text';
        const input = node(type === 'textarea' ? 'textarea' : 'input');
        if (type !== 'textarea') input.type = type;
        input.name = definition.name;
        input.required = Boolean(definition.required);
        if (definition.max) input.maxLength = definition.max;
        if (definition.pattern) input.pattern = definition.pattern;
        if (type === 'checkbox') {
            input.value = '1';
            input.checked = Boolean(definition.value);
        } else if (type !== 'file') {
            input.value = definition.value || '';
            input.placeholder = definition.placeholder || '';
            input.autocomplete = 'off';
            input.spellcheck = false;
        }
        label.append(node('span', definition.title), input);
        form.append(label);
        return input;
    }

    function closeDialog() {
        dialog.close();
        dialog.classList.remove('wgm-qr-dialog');
        dialog.replaceChildren();
    }

    function showForm(title, action, base, fields, note, onSuccess, submitText) {
        const heading = node('h3', title);
        heading.id = 'wgm-dialog-title';
        const form = node('form');
        form.autocomplete = 'off';
        if (note) form.append(node('p', note));
        for (const definition of fields) {
            field(form, definition);
        }
        const errors = node('p', '', 'wgm-error');
        errors.setAttribute('role', 'alert');
        const actions = node('div', null, 'wgm-actions');
        const submit = node('button', submitText || '保存', 'cbi-button cbi-button-apply');
        submit.type = 'submit';
        const cancel = button('取消', closeDialog);
        actions.append(submit, cancel);
        form.append(errors, actions);
        form.addEventListener('submit', async event => {
            event.preventDefault();
            if (changing) return;
            changing = true;
            submit.disabled = true;
            cancel.disabled = true;
            errors.textContent = '';
            const values = { ...base };
            for (const [key, value] of new FormData(form)) {
                if (typeof value === 'string') values[key] = value;
            }
            try {
                const result = await api(action, values);
                closeDialog();
                if (onSuccess) onSuccess(result, values);
                else if (result.public_key) message('已保存。接口公钥 ' + result.public_key);
                else message('已保存。');
            } catch (error) {
                if (dialog.open) errors.textContent = error.message;
                else message(error.message, true);
                return;
            } finally {
                changing = false;
                submit.disabled = false;
                cancel.disabled = false;
            }
            await refresh(false);
        });
        dialog.replaceChildren(heading, form);
        dialog.showModal();
        return form;
    }

    function tunnelForm(action, cfg) {
        const server = action === 'create_server';
        const editing = action === 'edit_client';
        const values = editing ? cfg.editable : {};
        const fields = editing ? [{
            name: 'display_name', title: '显示名称', value: cfg.display_name, placeholder: cfg.name, max: 96
        }] : [{
            name: 'iface', title: '接口名称', placeholder: server ? 'wg_home' : 'wg_remote',
            required: true, max: 15, pattern: '[A-Za-z][A-Za-z0-9_]*'
        }];
        if (!server) {
            fields.push(
                { name: 'file', title: '读取 .conf 文件（可选）', type: 'file' },
                { name: 'conf', title: '粘贴 .conf（可选，优先于下方字段）', type: 'textarea', max: 8192 }
            );
        }
        fields.push(
            { name: 'addresses', title: '本机隧道地址', required: server, value: values.address,
                placeholder: server ? '10.66.66.1/24, fd66::1/64' : '10.66.66.2/32' },
            { name: 'listen_port', title: '本机监听端口', required: server, value: values.listen_port, placeholder: server ? '51820' : '自动' },
            { name: 'mtu', title: 'MTU（可选）', value: values.mtu },
        );
        if (!server) {
            fields.push(
                { name: 'private_key', title: editing ? '本机新私钥（留空保留）' : '本机私钥（留空生成）', type: 'password', max: 44 },
                { name: 'public_key', title: '远端公钥', value: values.public_key, max: 44 },
                { name: 'preshared_key', title: editing ? '新预共享密钥（留空保留）' : '预共享密钥（可选）', type: 'password', max: 44 },
                { name: 'endpoint', title: '远端 Endpoint', value: values.endpoint, placeholder: 'vpn.example.com:51820' },
                { name: 'allowed_ips', title: '远端 AllowedIPs', value: values.allowed_ips, placeholder: '10.66.66.0/24, 192.168.50.0/24' },
                { name: 'dns', title: 'DNS（可选）', value: values.dns },
                { name: 'keepalive', title: '保活间隔（秒）', value: editing ? values.keepalive : '25' },
                { name: 'route', title: '为远端 AllowedIPs 安装系统路由（默认路由会影响旁路由的出口）', type: 'checkbox', value: values.routed },
            );
            if (editing) fields.push({ name: 'clear_psk', title: '清除已有的预共享密钥', type: 'checkbox' });
        }
        const form = showForm(server ? '新建服务端' : editing ? '编辑客户端隧道' : '新建客户端隧道', action,
            editing ? { iface: cfg.name } : {}, fields,
            editing ? '显示名称用于页面识别。修改网络参数时，运行中的隧道会短暂重连。' :
                '新接口保存后处于停止状态。防火墙区域与转发由 LuCI 防火墙页面管理。');
        if (!server) {
            const file = form.elements.namedItem('file');
            file.accept = '.conf,text/plain';
            file.addEventListener('change', async () => {
                const selected = file.files[0];
                if (!selected) return;
                try {
                    if (selected.size > 8192) throw new Error('配置文件不能超过 8 KB。');
                    form.elements.namedItem('conf').value = await selected.text();
                } catch (error) {
                    form.querySelector('[role=alert]').textContent = error.message;
                } finally {
                    file.value = '';
                }
            });
        }
    }

    function peerForm(cfg) {
        if (!cfg.defaults.effective_endpoint) return defaultsForm(cfg);
        showForm('新建客户端', 'add_peer', { iface: cfg.name }, [
            { name: 'label', title: '客户端名称', required: true, max: 96 },
        ], '自动分配地址并生成二维码。连接地址为 ' + cfg.defaults.effective_endpoint + '。', showClient, '创建并显示二维码');
    }

    function defaultsForm(cfg) {
        const values = cfg.defaults;
        showForm('服务端设置 · ' + cfg.name, 'server_defaults', { iface: cfg.name }, [
            { name: 'endpoint', title: 'Endpoint（留空使用旁路由 LAN 地址和监听端口）',
                value: values.endpoint, placeholder: values.effective_endpoint || 'vpn.example.com:51820' },
            { name: 'allowed_ips', title: '客户端 AllowedIPs（留空仅路由隧道网段）',
                value: values.allowed_ips, placeholder: '10.66.66.0/24, 192.168.9.0/24' },
            { name: 'dns', title: '客户端 DNS（可选）', value: values.dns },
            { name: 'keepalive', title: '保活间隔（秒）', value: values.keepalive, required: true },
            { name: 'retain', title: '在路由器保存配置，以便以后扫码或下载', type: 'checkbox', value: values.retain },
        ], '扫码和下载会使用最新设置。已经导入到设备的配置需要重新扫码或导入。');
    }

    function qrImage(config) {
        const qr = qrcodegen.QrCode.encodeText(config, qrcodegen.QrCode.Ecc.MEDIUM);
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        const dimension = qr.size + 8;
        svg.setAttribute('viewBox', '0 0 ' + dimension + ' ' + dimension);
        svg.setAttribute('role', 'img');
        svg.setAttribute('aria-label', 'WireGuard 客户端配置二维码');
        svg.style.background = '#fff';
        let modules = '';
        for (let y = 0; y < qr.size; y++) {
            for (let x = 0; x < qr.size; x++) {
                if (qr.getModule(x, y)) modules += 'M' + (x + 4) + ' ' + (y + 4) + 'h1v1h-1z';
            }
        }
        const path = document.createElementNS(svg.namespaceURI, 'path');
        path.setAttribute('d', modules);
        path.setAttribute('fill', '#000');
        svg.append(path);
        return svg;
    }

    function downloadClient(result) {
        const url = URL.createObjectURL(new Blob([result.config], { type: 'text/plain' }));
        const link = node('a');
        const name = (result.label || 'WireGuard').replace(/[^\p{L}\p{N}_-]+/gu, '-').replace(/^-+|-+$/g, '');
        link.href = url;
        link.download = (name || 'WireGuard') + '.conf';
        link.click();
        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    async function exportPeer(args, scan) {
        if (changing) return;
        changing = true;
        try {
            const result = await api('export_peer', args);
            if (scan) showClient(result);
            else downloadClient(result);
        } catch (error) {
            message(error.message, true);
        } finally {
            changing = false;
        }
    }

    function showClient(result) {
        const title = node('h3', (result.label || '客户端') + ' · 扫码导入');
        title.id = 'wgm-dialog-title';
        dialog.classList.add('wgm-qr-dialog');
        dialog.replaceChildren(title, node('p', '在手机 WireGuard App 中点「＋」→「扫描二维码」，扫码后给隧道命名并保存。'),
            node('p', result.addresses.join(', '), 'wgm-addresses'));
        try {
            dialog.append(qrImage(result.config));
        } catch (_) {
            dialog.append(node('p', '二维码无法生成，仍可下载配置。', 'wgm-error'));
        }
        const actions = node('div', null, 'wgm-actions');
        actions.append(button('下载 .conf', () => downloadClient(result), 'apply'), button('关闭', closeDialog));
        dialog.append(node('p', result.retained ? '此二维码含客户端私钥，可从客户端卡片再次打开。' :
            '关闭后无法再次打开此二维码，请先扫码或下载。', 'wgm-muted'));
        dialog.append(actions);
        dialog.showModal();
    }

    dialog.addEventListener('cancel', event => {
        event.preventDefault();
        if (!changing) closeDialog();
    });
    app.querySelector('[data-action=refresh]').addEventListener('click', () => refresh(true));
    for (const action of ['create_server', 'create_client']) {
        app.querySelector('[data-action=' + action + ']').addEventListener('click', () => tunnelForm(action));
    }
    refresh(true);
    window.setInterval(() => {
        if (!document.hidden && !dialog.open && !interfaces.querySelector('details[open]') &&
            !interfaces.contains(document.activeElement)) refresh(false);
    }, 10000);
})();
