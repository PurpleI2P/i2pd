window.util = {
    tr: {
        all: {
            get(ids = []) {
                return ids.length 
                    ? gl.torrents.filter(item => ids.includes(item.id))
                    : gl.torrents;
            },
            get_ids()         { return this.get().map(item => item.id) },
            count()           { return this.get().length },
            idx(id)           { return this.get().findIndex(item => item.id === id) },
            find_by_id(id)    { return this.get().find(item => item.id == id) },
            find_by_hash(hex) { return this.get().find(item => item.hashString == hex) },

            some_running() { return this.get().some(item => item.status > 0) },
            some_stopped() { return this.get().some(item => item.status == 0) }
        },

        sel: {
            get(ids = []) { 
                const objs = util.tr.all.get().filter(item => this.get_ids().includes(item.id));
                return ids.length 
                    ? objs.filter(item => ids.includes(item.id))
                    : objs;
            },
            get_ids()         { return gl.selected },
            count()           { return this.get_ids().length },
            idx(id)           { return this.get().findIndex(item => item.id === id) },
            find_by_id(id)    { return this.get().find(item => item.id == id) },
            find_by_hash(hex) { return this.get().find(item => item.hashString == hex) },

            some_running() { return this.get().some(item => item.status > 0) },
            some_stopped() { return this.get().some(item => item.status == 0) }
        },

        _redup(arr) { return [...new Set(arr)] },

        // clean non-exist ids
        mrproper()  { gl.selected = this._redup( this.sel.get_ids().filter(n => this.all.get_ids().includes(n)) ) },

        selected()      { return this.sel.count() > 0 },
        id_selected(id) { return this.sel.get_ids().includes(id) },
        all_selected()  { return this.sel.count() >= this.all.count() },

        select_id(id)        { gl.selected = this._redup( [...this.sel.get_ids(), id] )},
        select_ids(ids = []) { ids.forEach(id => this.select_id(id)) },
        select_all()         { gl.selected = this.all.get_ids() },

        deselect_id(id)        { gl.selected = this._redup( this.sel.get_ids().filter(n => n !== id) ) },
        deselect_ids(ids = []) { ids.forEach(id => this.deselect_id(id)) },
        deselect_all()         { gl.selected = [] },

        toggle_id(id)        { this.id_selected(id) ? this.deselect_id(id) : this.select_id(id) },
        toggle_ids(ids = []) { ids.forEach(id => this.toggle_id(id)) },
        toggle_all()         { this.all_selected() ? this.deselect_all() : this.select_all() }
    },

    copy: {
        text(text) {
            try {
                if (navigator.clipboard?.writeText)
                    navigator.clipboard.writeText(text);
            } catch {}

            const textarea = document.createElement("textarea");
            textarea.value = text;
            textarea.style.cssText = "position:fixed;opacity:0";
            document.body.appendChild(textarea);
            textarea.select();

            try {
                document.execCommand("copy");
            } finally {
                textarea.remove();
            }
        },

        magnets(torrents) {
            this.text(torrents.map(item => item.magnetLink).join("\n"));
        }
    },

    fmt: {
        bytes(bps) {
            if (!Number.isFinite(bps) || bps <= 0)
                return "0 B/s";

            const units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
            const i = Math.min(
                Math.floor(Math.log(bps) / Math.log(1024)),
                units.length - 1
            );

            return `${(bps / 1024 ** i).toFixed(2)} ${units[i]}`;
        },

        eta(torrent) {
            const speed = torrent.rateDownload || 0;
            const remaining = (torrent.totalSize || 0) * (1 - (torrent.percentDone || 0));

            if (speed <= 0) return "";

            const seconds = remaining / speed;

            switch (true) {
                case seconds < 60:
                    return `${Math.ceil(seconds)} sec`;

                case seconds < 3600:
                    return `${(seconds / 60).toFixed(1)} min`;

                case seconds < 86400:
                    return `${(seconds / 3600).toFixed(1)} h`;

                default:
                    return `${(seconds / 86400).toFixed(1)} days`;
            }
        },

        size(bytes) {
            if (!bytes) return "0 B";

            const units = ["B", "KB", "MB", "GB", "TB"];
            const i = Math.floor(Math.log(bytes) / Math.log(1024));

            return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
        }
    },

    rpc: {
        endpoint: "../rpc",

        async request(method, args = {}) {
            const res = await fetch(this.endpoint, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    method,
                    arguments: args
                })
            });

            return res.json();
        },

        stats: {
            dht_fields: [
                "numNodes", "numBuckets", "numTorrents", "numHeardFrom", "numFailedPeers"
            ],

            async session()    { return util.rpc.request("session-stats") },
            async dht()        { return util.rpc.request("dht-stats", { fields: this.dht_fields }) },
            async dht_hashes() { return util.rpc.request("dht-stats", { fields: ["torrentHashes"] }) }
        },

        torrent: {
            fields: [
                "id", "name", "status",
                "pieces", "pieceCount", "pieceSize",
                "rateDownload", "rateUpload",
                "downloadedEver", "uploadedEver",
                "totalSize", "haveValid", "percentDone",
                "files", "peers", "trackers", "trackerStats",
                "magnetLink", "hashString", "metadataPercentComplete"
            ],

            async get()                { return util.rpc.request("torrent-get", { fields: this.fields }) },
            async stop(ids = [])       { return util.rpc.request("torrent-stop", { ids }) },
            async start(ids = [])      { return util.rpc.request("torrent-start", { ids }) },
            async reannounce(ids = []) { return util.rpc.request("torrent-reannounce", { ids }) },
            async addUrl(url)          { return util.rpc.request("torrent-add", { filename: url }) },
            async addFile(b64)         { return util.rpc.request("torrent-add", { metainfo: b64 }) },

            async remove(ids = [], withFiles = false) {
                if (!ids.length) // we don't want to remove all torrents
                    return;

                return util.rpc.request("torrent-remove", {
                    ids: ids.length === 1 ? ids[0] : ids,
                    "delete-local-data": withFiles
                });
            }
        }
    },

    bitfield: {
        bytes(b64) {
            const decoded = window.atob(b64);
            const bytes = new Uint8Array(decoded.length);
            for (let i = 0; i < decoded.length; i++)
                bytes[i] = decoded.charCodeAt(i);
            return bytes
        },

        pieces(bytes, pieceCount) {
            const pieces = [];
            for (let i = 0; i < pieceCount; i++) {
                const have = bytes[i >> 3] & ( 0x80 >> (i & 7) );
                pieces[i] = have > 0 ? 1 : 0
            }
            return pieces;
        },

        // have / missing
        stats(pieces) {
            return [
                pieces.filter(num => num === 1).length,
                pieces.filter(num => num === 0).length
            ]
        },

        // [0,0,0,1,0,1,1,1,0,1,2] => [3,1,1,3,1,2]
        compress(pieces) {
            const compressed = [];
            for (const n of pieces) {
                compressed.length && compressed[compressed.length - 1].value === n 
                    ? compressed[compressed.length - 1].count++
                    : compressed.push({ value: n, count: 1 });
            }
            return compressed.map(x => x.count)
        },

        line(pieces, width) {
            const height = 40;
            const compressed = this.compress(pieces);
            const colors = pieces[0] // have first piece?
                ? ["#06D6A0", "#3a72ff"]
                : ["#3a72ff", "#06D6A0"];

            const canvas = document.createElement("canvas");
            const ctx = canvas.getContext("2d");
            const dpr = window.devicePixelRatio || 1;

            canvas.width = Math.round(width * dpr);
            canvas.height = Math.round(height * dpr);

            canvas.style.width = "100%";
            canvas.style.height = `${height}px`;
            canvas.style.display = "block";

            ctx.scale(dpr, dpr);

            let x = 0;
            compressed.forEach((count, i) => {
                const rectWidth = width * count / pieces.length;
                ctx.fillStyle = colors[i % 2];
                ctx.fillRect(x, 0, rectWidth, height);
                x += rectWidth;
            });

            return canvas;
        },

        grid(pieces, fs_width) {
            const canvas = document.createElement("canvas");
            const ctx = canvas.getContext("2d");

            // resizing columns
            const cols = pieces.length > 1000 
                ? 200
                : pieces.length > 500 
                    ? 100 
                    : 50;

            // number of rows depends on the number of pieces
            const rows = Math.ceil(pieces.length / cols);

            // cell size is determined by the fieldset width
            const cellSize = fs_width / cols;

            const width = fs_width;
            const height = rows * cellSize;

            const colors = ["#3a72ff", "#06D6A0"];

            const dpr = window.devicePixelRatio || 1;

            canvas.width = Math.round(width * dpr);
            canvas.height = Math.round(height * dpr);

            canvas.style.width = "100%";
            canvas.style.height = "auto";
            canvas.style.display = "block";

            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

            for (let i = 0; i < pieces.length; i++) {
                const row = Math.floor(i / cols);
                const col = i % cols;

                ctx.fillStyle = colors[pieces[i]];

                const x1 = Math.round( col * cellSize * dpr ) / dpr;
                const y1 = Math.round( row * cellSize * dpr ) / dpr;
                const x2 = Math.round( (col * cellSize + cellSize) * dpr ) / dpr;
                const y2 = Math.round( (row * cellSize + cellSize) * dpr ) / dpr;

                ctx.fillRect(x1, y1, x2 - x1, y2 - y1);
            }

            ctx.fillStyle = "#000000";

            const border = 1 / dpr;
            const count = pieces.length;

            const fullRows = Math.floor(count / cols);
            const actualRows = Math.ceil(count / cols);
            const remainder = count % cols;

            const bottomWidth = (remainder || cols) * cellSize;
            const bottomY = actualRows * cellSize;
            const rightX = Math.min(count, cols) * cellSize;

            // vertical borders
            for (let col = 1; col < cols; col++) {
                const x = Math.round(col * cellSize * dpr) / dpr;
                const height = (fullRows + (col <= remainder && remainder > 0 ? 1 : 0)) * cellSize;

                ctx.fillRect(x - border / 2, 0, border, height);
            }

            // horizontal borders
            for (let row = 1; row < actualRows; row++) {
                const y = Math.round(row * cellSize * dpr) / dpr;
                ctx.fillRect(0, y - border / 2, width, border);
            }

            // bottom
            ctx.fillRect(0, bottomY - border / 2, bottomWidth, border);

            // top
            ctx.fillRect(0, 0, rightX, border);

            // left
            ctx.fillRect(0, 0, border, rows * cellSize);

            // right
            ctx.fillRect(rightX - border, 0, border, fullRows * cellSize);

            return canvas;
        },

        fs(torrent) {
            if (!torrent?.pieceCount) 
                return document.createElement("div"); 

            const bytes = this.bytes(torrent.pieces);
            if (!bytes) 
                return document.createElement("div");

            const pieces = this.pieces(bytes, torrent.pieceCount);
            if (!pieces) 
                return document.createElement("div");

            const cvs = gl.bitfield_grid
                ? this.grid(pieces, el.details.clientWidth)
                : this.line(pieces, el.details.clientWidth)

            cvs.style.cursor = "pointer";
            cvs.addEventListener("click", () => {
                gl.bitfield_grid = !gl.bitfield_grid;
                refreshTable({ fetchTorrents: false });
            });

            const lable = document.createElement("legend");
            lable.textContent = 
                `Pieces: ${torrent.pieceCount} x ${util.fmt.size(torrent.pieceSize)}`;
            
            const stats = this.stats(pieces);
            if (stats[1])
                lable.textContent += ` (have ${stats[0]}, remaining ${stats[1]})`

            const fs = document.createElement("fieldset");
            fs.append(lable, cvs);
            return fs
        }

    },

    dialog: {
        async addMagnet() {
            const input = prompt("enter the magnet link:", "");

            if (!input) 
                return;

            const magnets = input.split(" ");

            magnets.forEach(async magnet => {
                const r = await util.rpc.torrent.addUrl(magnet)
                if (magnets.length === 1 && r.result !== "success")
                    alert(r.result);
            });

            await refreshTable();
        },

        async torrentRemove(ids = [], withFiles = false) {
            if (!ids.length) return;

            let warn = `remove the following torrents${withFiles ? ' WITH FILES' : ""}?\n\n`

            const objs = util.tr.all.get(ids)

            objs.forEach(obj => {
                warn += `#${obj.id} | ${obj.name}\n`
            });

            const confirmed = confirm(warn);
            if (!confirmed)
                return;

            await util.rpc.torrent.remove(ids, withFiles);
            await refreshTable({
                closeDetails:
                    gl.selector === ids[0] || util.tr.id_selected(gl.selector)
            });
        },

        async showDhtHashes() {
            const r = await util.rpc.stats.dht_hashes();
            if (!r?.arguments?.torrentHashes)
                return;

            const hashes = r.arguments.torrentHashes
            if (!hashes.length)
                return;

            let known = [],
                unknown = [];
            hashes.forEach(hash => {
                const q = util.tr.all.find_by_hash(hash);
                q ? known.push(`#${q.id}:\t${hash}`) : unknown.push(hash);
            });

            let result = '';
            if (known.length)
                result += `Known hashes:\n${known.join("\n")}`;
            if (unknown.length) {
                if (known.length) 
                    result += '\n\n'

                result += `Unknown hashes:\n${unknown.join("\n")}`;
            }

            if (result)
                alert(result);
        }
    },

    list: {
        session(args) {
            const list = document.createElement("div");

            const fields = {
                downloadedBytes: "Downloaded",
                uploadedBytes: "Uploaded"
            };

            Object.keys(args).forEach(key => {
                if (!(key in fields)) return;

                const cell = document.createElement("li");
                cell.textContent = `${fields[key]}: ${util.fmt.size(args[key])}`;
                list.appendChild(cell);
            });

            return list
        },

        dht(args) {
            const list = document.createElement("div");

            const fields = {
                supported: "Enabled",
                numNodes: "Nodes",
                numBuckets: "Buckets",
                numTorrents: "Torrents",
                numHeardFrom: "Heard from",
                numFailedPeers: "Failed peers"
            };

            Object.keys(args).forEach(key => {
                if (!(key in fields)) return;

                const cell = document.createElement("li");
                const text = `${fields[key]}: ${args[key]}`;

                if (key === "numTorrents" && args[key] > 0) {
                    const span = document.createElement("span");
                    span.textContent = text;
                    span.style.cssText = "cursor:pointer; text-decoration:underline";
                    span.onclick = util.dialog.showDhtHashes;
                    cell.appendChild(span);
                } else {
                    cell.textContent = text;
                }

                list.appendChild(cell);
            });

            return list
        },

        torrent(torrent) {
            if (!torrent) 
                return document.createElement("div"); 

            const keys = ["errorString", "status", "hashString", "magnetLink", "totalSize", "downloadedEver", "uploadedEver", "ratio"];
            const list = document.createElement("ul");

            const is_magnet = torrent.metadataPercentComplete < 1

            keys.forEach(key => {
                const cell = document.createElement("li");
                const value = torrent[key];

                switch (key) {
                    case "ratio":
                        const ratio = torrent.downloadedEver > 0
                            ? torrent.uploadedEver / torrent.downloadedEver
                            : 0;

                        if (ratio)
                            cell.textContent = `Ratio: ${ratio.toFixed(2)}`;
                        break;

                    case "totalSize":
                        if (!value)
                            break;
                            
                        cell.textContent =
                            `Total size: ${util.fmt.size(torrent.totalSize)}`;

                        if (torrent.haveValid === 0 || torrent.haveValid === torrent.totalSize)
                            break;

                        cell.textContent += 
                            ` (have ${util.fmt.size(torrent.haveValid)}, remaining ${util.fmt.size(torrent.totalSize - torrent.haveValid)})`
                        break;

                    case "downloadedEver":
                        if (value)
                            cell.textContent = `Downloaded: ${util.fmt.size(value)}`;
                        break;

                    case "uploadedEver":
                        if (value)
                            cell.textContent = `Uploaded: ${util.fmt.size(value)}`;
                        break;

                    case "hashString":
                        if (value)
                            cell.textContent = `Hash: ${value}`;
                        break;

                    case "magnetLink":
                        cell.textContent = `Magnet: `;

                        const link = document.createElement('a');
                        link.href = value;
                        link.textContent = value.length > 60 
                            ? value.slice(0, 60) + '...' 
                            : value;

                        link.addEventListener("click", event => {
                            event.preventDefault();
                            util.copy.magnets([torrent])
                        });
                        cell.appendChild(link);

                        break;

                    case "status":
                        const enumStatus = [
                            "Stopped",
                            "QueuedToVerifyLocalData",
                            "VerifyingLocalData",
                            "QueuedToDownload",
                            "Downloading",
                            "QueuedToSeed",
                            "Seeding"
                        ];

                        cell.textContent = `Status: ${enumStatus[value] || value}`;
                        if (value === 4 && is_magnet)
                            cell.textContent = 'Status: Retrieving metadata'
                        break;

                    case "errorString":
                        if (value) {
                            cell.textContent = `Error: ${value || "None"}`;
                            cell.style.fontWeight = "bold";
                            cell.style.color = "#ff3333";
                        }
                        break;
                }

                if (cell.textContent)
                    list.appendChild(cell);
            });

            return list
        }
    },

    table: {
        eta_sec(torrent) {
            const speed = torrent.rateDownload || 0;
            const remaining = (torrent.totalSize || 0) * (1 - (torrent.percentDone || 0));
            return speed <= 0 
                ? 0 
                : remaining / speed
        },

        file_progress(file) {
            return file.length > 0 
                ? Math.min(
                    1,
                    Math.max(
                        0, 
                        file.bytesCompleted / file.length
                    )
                ) : 0;
        },

        torrents(torrents, sorting) {
            if (!torrents.length) 
                return document.createElement("div")

            const table_cols = ["_select_", "id", "name", "progress", "S / L", "speedDw", "speedUp", "size", "have", "eta"];
            const locale_row = sorting.row === 2; // "name"

            if (sorting.enabled) {
                const dir = locale_row ^ sorting.reverse ? 1 : -1;

                torrents.sort((a, b) => {
                    switch (sorting.row) {
                        case 1: // id
                            return (a.id - b.id) * dir;

                        case 2: // name
                            return a.name.localeCompare(b.name) * dir;

                        case 3: // progress
                            return (a.percentDone - b.percentDone) * dir;

                        case 4: // S / L
                            return (a.peers.length - b.peers.length) * dir;

                        case 5: // speedDw
                            return (a.rateDownload - b.rateDownload) * dir;

                        case 6: // speedUp
                            return (a.rateUpload - b.rateUpload) * dir;

                        case 7: // size
                            return (a.totalSize - b.totalSize) * dir;

                        case 8: // have
                            // skip empty rows
                            const a_hv = a.haveValid == a.totalSize ? 0 : a.haveValid;
                            const b_hv = b.haveValid == b.totalSize ? 0 : b.haveValid;
                        
                            return (a_hv - b_hv) * dir;

                        case 9: // eta
                            return (this.eta_sec(a) - this.eta_sec(b)) * dir;

                        default:
                            return 0;
                    }
                });
            }

            let allDw = allUp = allSize = 0;

            const table = document.createElement("table");
            table.className = "compact-table";

            table_cols.forEach((item, index) => {
                const th = document.createElement("th");
                th.style.whiteSpace = 'nowrap'

                if (item === "_select_")
                {
                    if (!util.tr.selected())
                        return;

                    const checkbox = document.createElement("input");
                    checkbox.type = "checkbox";
                    th.style.textAlign = "center";
                    
                    if (util.tr.all_selected())
                        checkbox.checked = true;

                    checkbox.addEventListener("change", () => {
                        util.tr.toggle_all();
                        refreshTable({ fetchTorrents: false });
                    });

                    th.append(checkbox);
                    table.appendChild(th);

                    return;
                }

                th.textContent = item;
                th.style.cursor = "pointer";
                th.addEventListener("mouseenter", () => { th.style.textDecoration = "underline" });
                th.addEventListener("mouseleave", () => { th.style.textDecoration = "none" });
                th.addEventListener("mousedown", event => { event.preventDefault() });
                th.addEventListener("click", event => {
                    event.preventDefault();
                    let fetchTorrents = false;

                    if (sorting.enabled && index === sorting.row) {
                        if (!sorting.reverse)
                            sorting.reverse = true;
                        else {
                            sorting.enabled = false;
                            sorting.reverse = false;
                            fetchTorrents = true; // fetch original order
                        }
                    } else {
                        sorting.enabled = true;
                        sorting.reverse = false;
                        sorting.row = index;
                    }

                    refreshTable({ fetchTorrents: fetchTorrents });
                });

                if (sorting.enabled && index === sorting.row)
                    th.textContent += locale_row ^ sorting.reverse ? '↑' : '↓'

                table.appendChild(th);
            });

            torrents.forEach((torrent, index) => {
                const tr = document.createElement("tr");
                const is_magnet = torrent.metadataPercentComplete < 1
                
                table_cols.forEach(key => {
                    if (key === "_select_" && !util.tr.selected())
                        return;

                    const cell = document.createElement("td");

                    switch (key) {
                        case "_select_":
                            const checkbox = document.createElement("input");
                            checkbox.type = "checkbox";

                            if (util.tr.id_selected(torrent.id))
                                checkbox.checked = true;

                            checkbox.addEventListener("change", () => {
                                util.tr.toggle_id(torrent.id);
                                refreshTable({ fetchTorrents: false });
                            });
                            
                            cell.style.textAlign = "center";
                            cell.append(checkbox);
                            break;

                        case "id":
                            cell.textContent = torrent.id || "?";
                            break;

                        case "name":
                            cell.textContent = torrent.name || "__none__";
                            if (torrent.errorString) {
                                cell.style.fontWeight = "bold";
                                cell.style.color = "#ff3333";
                            }
                            break;

                        case "progress": {
                            cell.className = "progress-cell";

                            const progress = is_magnet ? torrent.metadataPercentComplete : torrent.percentDone;
                            const percent = Math.max(
                                0, 
                                Math.min(
                                    100,
                                    (progress * 100).toFixed(1)
                                )
                            )

                            let pr_color = "#E5E7EB"
                            let pr_lable = is_magnet ? '🧲' : `${percent}%`;
                            switch (torrent.status) {
                                case 4:
                                    // downloading
                                    pr_color = "#44abff";
                                    if (!torrent.rateDownload && !is_magnet) {
                                        // stalled or idle
                                        pr_color = "#0072cf";
                                        pr_lable += torrent.peers.length 
                                            ? ', stalled'
                                            : ', idle'
                                    }
                                    break;
                                case 6:
                                    // seeding
                                    pr_color = "#00FF5A";
                                    break;
                                case 0:
                                    // paused + done
                                    pr_color = "#009133";
                                    if (torrent.percentDone < 1) {
                                        // paused
                                        pr_color = "#ffd000";
                                        pr_lable += ', paused'
                                    }
                                    break;
                            }

                            const progressBar = document.createElement("div");
                            progressBar.className = "progress-bar";

                            const progressFill = document.createElement("div");
                            progressFill.className = "progress-fill";
                            progressFill.style.width = `${percent}%`;
                            progressFill.style.backgroundColor = pr_color;
                            progressBar.appendChild(progressFill);

                            const progressText = document.createElement("div");
                            progressText.className = "progress-text";
                            progressText.textContent = pr_lable

                            cell.append(progressBar, progressText);
                            break;
                        }

                        case "S / L":
                            let seeders = leechers = 0;

                            torrent.peers.forEach(peer => {
                                if (peer.progress !== 0)
                                    peer.progress === 1 ? seeders++ : leechers++
                            });

                            if (torrent.status === 6) // seeding
                                cell.textContent = leechers || "" 
                            else if (seeders || leechers) // leeching
                                cell.textContent = `${seeders} / ${leechers}`;

                            break;

                        case "speedDw":
                            cell.textContent = torrent.rateDownload 
                                ? util.fmt.bytes(torrent.rateDownload) 
                                : "";

                            allDw += torrent.rateDownload;
                            break;

                        case "speedUp":
                            cell.textContent = torrent.rateUpload 
                                ? util.fmt.bytes(torrent.rateUpload)
                                : "";

                            allUp += torrent.rateUpload;
                            break;

                        case "size":
                            cell.textContent = torrent.totalSize
                                ? util.fmt.size(torrent.totalSize) 
                                : "";

                            allSize += torrent.totalSize
                            break;

                        case "have":
                            cell.textContent = (torrent.haveValid === 0 || torrent.haveValid === torrent.totalSize) 
                                ? "" 
                                : util.fmt.size(torrent.haveValid);

                            break;

                        case "eta":
                            cell.textContent = util.fmt.eta(torrent);
                            break;
                    }

                    if (key !== "name")
                        cell.style.whiteSpace = 'nowrap'

                    tr.appendChild(cell);
                });

                // zebra
                if (index % 2)
                    tr.style.backgroundColor = "#ebebeb";

                const is_selector = gl.selector === torrent.id;
                const is_selected = util.tr.id_selected(torrent.id);

                if (is_selector)
                    tr.style.backgroundColor = "#ff9900ce";

                if (is_selected) {
                    tr.style.backgroundColor = "#0000a1";
                    tr.style.color = "#fff";
                }

                if (is_selector && is_selected)
                    tr.style.backgroundColor = "#8050d0";

                tr.dataset.id = torrent.id
                tr.classList.add("highlight-row");

                table.appendChild(tr);
            });

            // bottom row
            const tr = document.createElement("tr");
            table_cols.forEach(key => {
                if (key === "_select_" && !util.tr.selected())
                    return;

                const cell = document.createElement("td");

                switch (key) {
                    case "speedDw":
                        cell.textContent = allDw 
                            ? util.fmt.bytes(allDw) 
                            : "";

                        break;

                    case "speedUp":
                        cell.textContent = allUp 
                            ? util.fmt.bytes(allUp) 
                            : "";

                        break;

                    case "size":
                        cell.textContent = allSize 
                            ? util.fmt.size(allSize) 
                            : "";

                        break;
                }
                
                cell.style.fontWeight = "bold";
                cell.style.whiteSpace = 'nowrap'
                tr.appendChild(cell);
            });
            table.appendChild(tr);

            document.title = `↓${util.fmt.bytes(allDw)} ↑${util.fmt.bytes(allUp)}`;
            
            const lable = document.createElement("legend");
            lable.textContent = `Torrents: ${util.tr.all.count()}`
            if (util.tr.selected())
                lable.textContent += `, Selected: ${util.tr.sel.count()}`

            const fs = document.createElement("fieldset");
            fs.append(lable, table);
            return fs
        },

        files(files_, sorting) {
            if (!files_?.length) 
                return document.createElement("div"); 

            let files = files_.slice() // keep original order

            // files fields
            const table_cols = ["name", "progress", "size", "have", "left"];
            const locale_row = sorting.row === 0; // "name"

            if (sorting.enabled) {
                const dir = locale_row ^ sorting.reverse ? 1 : -1;

                files.sort((a, b) => {
                    switch (sorting.row) {
                        case 0: // name
                            return a.name.localeCompare(b.name) * dir;

                        case 1: // progress
                            return (this.file_progress(a) - this.file_progress(b)) * dir;

                        case 2: // size
                            return (a.length - b.length) * dir;

                        case 3: // have
                            return (a.length - b.length) * dir;

                        case 4: // left
                            const a_bc = a.length - a.bytesCompleted;
                            const b_bc = b.length - b.bytesCompleted;

                            return (a_bc - b_bc) * dir;

                        default:
                            return 0;
                    }
                });
            }

            // files table
            const table = document.createElement("table");
            table.className = "compact-table";

            // files table header
            table_cols.forEach((item, index) => {
                const th = document.createElement("th");
                th.style.whiteSpace = 'nowrap'

                th.textContent = item;
                th.style.cursor = "pointer";
                th.addEventListener("mouseenter", () => { th.style.textDecoration = "underline" });
                th.addEventListener("mouseleave", () => { th.style.textDecoration = "none" });
                th.addEventListener("mousedown", event => { event.preventDefault() });
                th.addEventListener("click", event => {
                    event.preventDefault();

                    if (sorting.enabled && index === sorting.row) {
                        if (!sorting.reverse)
                            sorting.reverse = true;
                        else {
                            sorting.enabled = false;
                            sorting.reverse = false;
                        }
                    } else {
                        sorting.enabled = true;
                        sorting.reverse = false;
                        sorting.row = index;
                    }

                    refreshTable({ fetchTorrents: false });
                });

                if (sorting.enabled && index === sorting.row)
                    th.textContent += locale_row ^ sorting.reverse ? '↑' : '↓'

                table.appendChild(th);
            });

            // files table data
            files.forEach((file, index) => {
                const tr = document.createElement("tr");

                table_cols.forEach(key => {
                    const cell = document.createElement("td");
                    const value = file[key];

                    switch (key) {
                        case "name":
                            cell.textContent = value || "__none__";
                            break;
                        case "progress":
                            cell.className = "progress-cell";

                            const progress = this.file_progress(file)

                            const percent = +(progress * 100).toFixed(1);

                            const progressFill = document.createElement("div");
                            progressFill.className = "progress-fill";
                            progressFill.style.width = `${percent}%`;
                            progressFill.style.backgroundColor = progress === 1 ? "#00FF5A" : "#4DAFFF";

                            const progressBar = document.createElement("div");
                            progressBar.className = "progress-bar";
                            progressBar.appendChild(progressFill);

                            const progressText = document.createElement("div");
                            progressText.className = "progress-text";
                            progressText.textContent = `${percent}%`;

                            cell.append(progressBar, progressText);
                            break;

                        case "size":
                            cell.textContent = util.fmt.size(file.length);
                            break;

                        case "have":
                            cell.textContent = file.bytesCompleted 
                                ? util.fmt.size(file.bytesCompleted) 
                                : "";
                            break;

                        case "left":
                            cell.textContent = (file.length - file.bytesCompleted) 
                                ? util.fmt.size(file.length - file.bytesCompleted) 
                                : "";
                            break;
                    }

                    if (key !== "name")
                        cell.style.whiteSpace = 'nowrap'

                    tr.appendChild(cell);
                });

                // zebra
                if (index % 2)
                    tr.style.backgroundColor = "#ebebeb";

                table.appendChild(tr);
            });

            const lable = document.createElement("legend");
            lable.textContent = `Files: ${files.length}`

            const fs = document.createElement("fieldset");
            fs.append(table, lable);
            return fs
        },

        trackers(trackerStats_, sorting) {
            if (!trackerStats_?.length) 
                return document.createElement("div"); 

            let trackerStats = trackerStats_.slice() // keep original order

            // trackers fields
            const table_cols = [
                "id", "announce", 
                "peers", "seeders", "leechers", 
                "lastAnnounceResult", "lastAnnounceTime", "nextAnnounceTime"
            ];
            const locale_row = sorting.row === 1 || sorting.row === 5; // "announce", "lastAnnounceResult"

            if (sorting.enabled) {
                const dir = locale_row ^ sorting.reverse ? 1 : -1;

                trackerStats.sort((a, b) => {
                    switch (sorting.row) {
                        case 0: // id
                            return (a.id - b.id) * dir;

                        case 1: // announce
                            return a.announce.localeCompare(b.announce) * dir;

                        case 2: // peers
                            return (a.lastAnnouncePeerCount - b.lastAnnouncePeerCount) * dir;

                        case 3: // seeders
                            return (a.seederCount - b.seederCount) * dir;

                        case 4: // leechers
                            return (a.leecherCount - b.leecherCount) * dir;

                        case 5: // lastAnnounceResult
                            return a.lastAnnounceResult.localeCompare(b.lastAnnounceResult) * dir;

                        case 6: // lastAnnounceTime
                            return (a.lastAnnounceTime - b.lastAnnounceTime) * dir;

                        case 7: // nextAnnounceTime
                            return (a.nextAnnounceTime - b.nextAnnounceTime) * dir;

                        default:
                            return 0;
                    }
                });
            }

            // trackers table
            const table = document.createElement("table");
            table.className = "compact-table";

            // trackers table header
            table_cols.forEach((item, index) => {
                const th = document.createElement("th");
                th.style.whiteSpace = 'nowrap'

                th.textContent = item;
                th.style.cursor = "pointer";
                th.addEventListener("mouseenter", () => { th.style.textDecoration = "underline" });
                th.addEventListener("mouseleave", () => { th.style.textDecoration = "none" });
                th.addEventListener("mousedown", event => { event.preventDefault() });
                th.addEventListener("click", event => {
                    event.preventDefault();

                    if (sorting.enabled && index === sorting.row) {
                        if (!sorting.reverse)
                            sorting.reverse = true;
                        else {
                            sorting.enabled = false;
                            sorting.reverse = false;
                        }
                    } else {
                        sorting.enabled = true;
                        sorting.reverse = false;
                        sorting.row = index;
                    }

                    refreshTable({ fetchTorrents: false });
                });

                if (sorting.enabled && index === sorting.row)
                    th.textContent += locale_row ^ sorting.reverse ? '↑' : '↓'

                table.appendChild(th);
            });

            trackerStats.forEach((tracker, index) => {
                const tr = document.createElement("tr");

                table_cols.forEach(key => {
                    const cell = document.createElement("td");
                    const value = tracker[key];

                    switch (key) {
                        case "announce":
                        case "lastAnnounceResult":
                            cell.textContent = value || "";
                            break;
                        case "id":
                            cell.textContent = value;
                            break;
                        case "seeders":
                            cell.textContent = tracker.seederCount || 0;
                            break;
                        case "leechers":
                            cell.textContent = tracker.leecherCount || 0;
                            break;
                        case "peers":
                            cell.textContent = tracker.lastAnnouncePeerCount || 0;
                            break;
                        case "lastAnnounceTime":
                        case "nextAnnounceTime":
                            cell.textContent = new Date(value * 1000).toLocaleString();
                            break;
                    }

                    if (key !== "announce")
                        cell.style.whiteSpace = 'nowrap'

                    tr.appendChild(cell);
                });

                // zebra
                if (index % 2)
                    tr.style.backgroundColor = "#ebebeb";
                
                table.appendChild(tr);
            });

            const lable = document.createElement("legend");
            lable.textContent = `Trackers: ${trackerStats.length}`

            const fs = document.createElement("fieldset");
            fs.append(lable, table);
            return fs
        },

        peers(peers_, sorting) {
            if (!peers_?.length) 
                return document.createElement("div"); 

            let peers = peers_.slice() // keep original order

            // peer fields
            const table_cols = [
                "address", "client", "flags", "progress", "speedDw", "speedUp"
            ];
            const locale_row = sorting.row === 0 || sorting.row === 1; // "address", "client"

            if (sorting.enabled) {
                const dir = locale_row ^ sorting.reverse ? 1 : -1;

                peers.sort((a, b) => {
                    switch (sorting.row) {
                        case 0: // address
                            return a.address.localeCompare(b.address) * dir;

                        case 1: // client
                            return a.clientName.localeCompare(b.clientName) * dir;

                        case 2: // flags
                            return (a.flagStr.length - b.flagStr.length) * dir;

                        case 3: // progress
                            return (a.progress - b.progress) * dir;

                        case 4: // speedDw
                            return (a.rateToClient - b.rateToClient) * dir;

                        case 5: // speedUp
                            return (a.rateToPeer - b.rateToPeer) * dir;

                        default:
                            return 0;
                    }
                });
            }

            // peer table
            const table = document.createElement("table");
            table.className = "compact-table";

            // peer table header
            table_cols.forEach((item, index) => {
                const th = document.createElement("th");
                th.style.whiteSpace = 'nowrap'

                th.textContent = item;
                th.style.cursor = "pointer";
                th.addEventListener("mouseenter", () => { th.style.textDecoration = "underline" });
                th.addEventListener("mouseleave", () => { th.style.textDecoration = "none" });
                th.addEventListener("mousedown", event => { event.preventDefault() });
                th.addEventListener("click", event => {
                    event.preventDefault();

                    if (sorting.enabled && index === sorting.row) {
                        if (!sorting.reverse)
                            sorting.reverse = true;
                        else {
                            sorting.enabled = false;
                            sorting.reverse = false;
                        }
                    } else {
                        sorting.enabled = true;
                        sorting.reverse = false;
                        sorting.row = index;
                    }

                    refreshTable({ fetchTorrents: false });
                });

                if (sorting.enabled && index === sorting.row)
                    th.textContent += locale_row ^ sorting.reverse ? '↑' : '↓'

                table.appendChild(th);
            });

            // peer table data
            peers.forEach((peer, index) => {
                const tr = document.createElement("tr");

                table_cols.forEach(key => {
                    const cell = document.createElement("td");
                    const value = peer[key];

                    switch (key) {
                        case "address":
                            cell.textContent = value;
                            break;

                        case "client":
                            cell.textContent = peer.clientName || "";
                            break;

                        case "flags":
                            cell.textContent = peer.flagStr || "";
                            break;

                        case "progress":
                            cell.className = "progress-cell";

                            const percent = Math.max(
                                0, 
                                Math.min(
                                    100, 
                                    (peer.progress * 100).toFixed(1)
                                )
                            )

                            const progressBar = document.createElement("div");
                            progressBar.className = "progress-bar";

                            const progressFill = document.createElement("div");
                            progressFill.className = "progress-fill";
                            progressFill.style.width = `${percent}%`;
                            progressFill.style.backgroundColor = peer.progress >= 1 ? "#00FF5A" : "#4DAFFF";
                            progressBar.appendChild(progressFill);

                            const progressText = document.createElement("div");
                            progressText.className = "progress-text";
                            progressText.textContent = `${percent}%`;

                            cell.append(progressBar, progressText);
                            break;

                        case "speedDw":
                            cell.textContent = peer.rateToClient 
                                ? util.fmt.bytes(peer.rateToClient) 
                                : "";
                            break;

                        case "speedUp":
                            cell.textContent = peer.rateToPeer 
                                ? util.fmt.bytes(peer.rateToPeer) 
                                : "";
                            break;
                    }

                    tr.appendChild(cell);
                });

                // zebra
                if (index % 2)
                    tr.style.backgroundColor = "#ebebeb";

                table.appendChild(tr);
            });

            const lable = document.createElement("legend");
            lable.textContent = `Peers: ${peers.length}`

            const fs = document.createElement("fieldset");
            fs.append(lable, table);
            return fs
        }
    }
};