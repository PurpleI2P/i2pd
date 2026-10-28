window.util = {
    sel: {
        redup(arr)       { return [...new Set(arr)] },

        getObjects()     { return (torrents || []).filter(item => (selected_torrents || []).includes(item.id)); },
        getAllIDs()      { return torrents.map(item => item.id) },
        idsToObj(ids)    { return torrents.filter(item => (ids || []).includes(item.id)) },
        objIdx(id)       { return torrents.findIndex(item => item.id === id) },

        isEnabled()      { return Boolean(selected_torrents.length) },
        isSelected(id)   { return selected_torrents.includes(id) },
        isSomeRunning()  { return this.getObjects().some(item => item.status > 0) },
        isSomeStopped()  { return this.getObjects().some(item => item.status == 0) },
        allChecked()     { return torrents.length === selected_torrents.length },

        deselectAll()    { selected_torrents = [] },
        selectAll()      { selected_torrents = this.getAllIDs() },
        toggleAll()      { this.allChecked() ? this.deselectAll() : this.selectAll() },
        clearIDs()       { selected_torrents = selected_torrents.filter(n => this.getAllIDs().includes(n)) },

        toggleID(id)     { this.isSelected(id) ? this.deselectID(id) : this.selectID(id) },
        toggleIDs(ids)   { (ids || []).forEach(id => this.toggleID(id)) },

        deselectID(id)   { selected_torrents = this.redup( selected_torrents.filter(n => n !== id)) },
        deselectIDs(ids) { (ids || []).forEach(id => this.deselectID(id)) },

        selectID(id)     { selected_torrents = this.redup( [...selected_torrents, id] )},
        selectIDs(ids)   { (ids || []).forEach(id => this.selectID(id)) }
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

    list: {
        session(session_stats) {
            const list = document.createElement("div");

            const fields = {
                downloadedBytes: "Downloaded",
                uploadedBytes: "Uploaded"
            };

            Object.keys(session_stats).forEach(key => {
                if (key in fields) {
                    const cell = document.createElement("li");
                    cell.textContent = `${fields[key]}: ${util.fmt.size(session_stats[key])}`;
                    list.appendChild(cell);
                }
            });

            return list
        },

        dht(dht_stats) {
            const list = document.createElement("div");

            const fields = {
                supported: "Enabled",
                numNodes: "Nodes",
                numBuckets: "Buckets",
                numTorrents: "Torrents",
                numHeardFrom: "Heard from",
                numFailedPeers: "Failed peers"
            };

            Object.keys(dht_stats).forEach(key => {
                if (key in fields) {
                    const cell = document.createElement("li");
                    cell.textContent = `${fields[key]}: ${dht_stats[key]}`;
                    list.appendChild(cell);
                }
            });

            return list
        },

        torrent(torrent) {
            if (!torrent) 
                return document.createElement("div"); 

            const keys = ["status", "hashString", "magnetLink", "pieceCount", "errorString"];
            const list = document.createElement("ul");

            keys.forEach(key => {
                const cell = document.createElement("li");
                const value = torrent[key];

                switch (key) {
                    case "hashString":
                        if (value)
                            cell.textContent = `Hash: ${value}`;
                        break;

                    case "magnetLink":
                        cell.textContent = `Magnet: `;

                        const link = document.createElement('a');
                        link.textContent = value.length > 60 ? value.slice(0, 60) + '...' : value;
                        link.href = value;

                        link.addEventListener("click", event => {
                            event.preventDefault();
                            util.copy.magnets([torrent])
                        });
                        cell.appendChild(link);

                        break;

                    case "pieceCount":
                        if (value)
                            cell.textContent = `Pieces: ${value} x ${util.fmt.size(torrent.pieceSize)}`;
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

                        if (value >= 0 && value < enumStatus.length)
                            cell.textContent = `Status: ${enumStatus[value]}`;
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
        torrents(torrents) {
            if (!torrents?.length) 
                return {
                    "table": document.createElement("div"),
                    "allDw": 0,
                    "allUp": 0,
                    "allSize": 0
                } 

            let allDw = allUp = allSize = 0;

            const table_cols = ["_select_", "id", "name", "progress", "S / L", "speedDw", "speedUp", "size", "have", "eta"];

            const table = document.createElement("table");
            table.className = "compact-table";

            table_cols.forEach((item) => {
                const th = document.createElement("th");

                if (item === "_select_")
                {
                    if (!util.sel.isEnabled())
                        return;

                    const checkbox = document.createElement("input");
                    checkbox.type = "checkbox";
                    th.style.textAlign = "center";
                    
                    if (util.sel.allChecked())
                        checkbox.checked = true;

                    checkbox.addEventListener("change", () => {
                        util.sel.toggleAll();
                        refreshTable({ fetchTorrents: false });
                    });

                    th.append(checkbox);
                    table.appendChild(th);

                    return;
                }

                th.textContent = item;
                th.style.whiteSpace = 'nowrap'

                table.appendChild(th);
            });

            torrents.forEach((torrent, index) => {
                const tr = document.createElement("tr");
                const is_magnet = torrent.metadataPercentComplete < 1
                
                table_cols.forEach(key => {
                    if (key === "_select_" && !util.sel.isEnabled())
                        return;

                    const cell = document.createElement("td");

                    switch (key) {
                        case "_select_":
                            const checkbox = document.createElement("input");
                            checkbox.type = "checkbox";

                            if (util.sel.isSelected(torrent.id))
                                checkbox.checked = true;

                            checkbox.addEventListener("change", () => {
                                util.sel.toggleID(torrent.id);
                                refreshTable({ fetchTorrents: false });
                            });
                            
                            cell.style.textAlign = "center";
                            cell.append(checkbox);
                            break;

                        case "id":
                            cell.textContent = torrent.id || " ";
                            break;

                        case "name":
                            cell.textContent = torrent.name || " ";
                            if (torrent.errorString) {
                                cell.style.fontWeight = "bold";
                                cell.style.color = "#ff3333";
                            }
                            break;

                        case "progress": {
                            cell.className = "progress-cell";

                            const percent = Math.max(
                                0, 
                                Math.min(
                                    100,
                                    (torrent.percentDone * 100).toFixed(1)
                                )
                            )

                            let pr_color = "#E5E7EB"
                            let pr_lable = is_magnet ? '🧲' : `${percent}%`;
                            switch (torrent.status) {
                                case 4:
                                    pr_color = "#44abff"; // downloading
                                    if (!torrent.rateDownload && !is_magnet) {
                                        pr_color = "#0072cf";
                                        pr_lable += ', stalled'
                                    }
                                    break;
                                case 6:
                                    pr_color = "#00FF5A"; // seeding
                                    break;
                                case 0:
                                    pr_color = "#009133"; // paused + done
                                    if (torrent.percentDone < 1) {
                                        pr_color = "#ffd000"; // paused
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

                const is_selector = selected_torrent === torrent.id;
                const is_selected = util.sel.isSelected(torrent.id);

                if (is_selector)
                    tr.style.backgroundColor = "#ff9900ce";

                if (is_selected) {
                    tr.style.backgroundColor = "#0000a1";
                    tr.style.color = "#fff";
                }

                if (is_selector && is_selected)
                    tr.style.backgroundColor = "#8050d0";

                tr.dataset.id = torrent.id
                tr.classList.add("torrent-row");

                table.appendChild(tr);
            });

            // bottom row
            const tr = document.createElement("tr");
            table_cols.forEach(key => {
                if (key === "_select_" && !util.sel.isEnabled())
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

            return {
                "table": table,
                "allDw": allDw,
                "allUp": allUp,
                "allSize": allSize
            }
        },

        files(files) {
            if (!files?.length) 
                return document.createElement("div"); 

            // files frame
            const fs = document.createElement("fieldset");

            // files frame label
            const fs_lable = document.createElement("legend");
            fs_lable.textContent = `Files: ${files.length}`
            fs.appendChild(fs_lable);

            // files fields
            const table_cols = ["name", "progress", "size", "have", "left"];

            // files table
            const table = document.createElement("table");
            table.className = "compact-table";

            // files table header
            table_cols.forEach((item) => {
                const th = document.createElement("th");
                th.textContent = item;
                th.style.whiteSpace = 'nowrap'
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
                            cell.textContent = value;
                            break;
                        case "progress":
                            cell.className = "progress-cell";

                            const progress = file.length > 0 ? 
                                Math.min(
                                    1,
                                    Math.max(
                                        0, 
                                        file.bytesCompleted / file.length
                                    )
                                ) : 0;

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

            fs.appendChild(table);

            return fs
        },

        trackers(trackerStats) {
            if (!trackerStats?.length) 
                return document.createElement("div"); 

            const fs = document.createElement("fieldset");

            // trackers frame label
            const fs_lable = document.createElement("legend");
            fs_lable.textContent = `Trackers: ${trackerStats.length}`
            fs.appendChild(fs_lable);

            // trackers fields
            const table_cols = [
                "id", "announce", 
                "peers", "seeders", "leechers", 
                "lastAnnounceResult", "lastAnnounceTime", "nextAnnounceTime"
            ];

            // trackers table
            const table = document.createElement("table");
            table.className = "compact-table";

            // trackers table header
            table_cols.forEach((item) => {
                const th = document.createElement("th");
                th.textContent = item;
                th.style.whiteSpace = 'nowrap'
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

            fs.appendChild(table);

            return fs
        },

        peers(peers) {
            if (!peers?.length) 
                return document.createElement("div"); 

            // peers frame
            const fs = document.createElement("fieldset");

            // peers frame label
            const fs_lable = document.createElement("legend");
            fs_lable.textContent = `Peers: ${peers.length}`
            fs.appendChild(fs_lable);

            // peer fields
            const table_cols = [
                "address", "client", "flags", 
                "progress", "speedDw", "speedUp"
            ];

            // peer table
            const table = document.createElement("table");
            table.className = "compact-table";

            // peer table header
            table_cols.forEach((item) => {
                const th = document.createElement("th");
                th.textContent = item;
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

            fs.appendChild(table);

            return fs
        }
    }
};