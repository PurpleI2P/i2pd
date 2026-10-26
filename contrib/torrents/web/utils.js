window.utils = {
    formatBytes(bytesPerSec) {
        if (!Number.isFinite(bytesPerSec) || bytesPerSec <= 0)
            return "0 B/s";

        const units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
        const i = Math.min(
            Math.floor(Math.log(bytesPerSec) / Math.log(1024)),
            units.length - 1
        );

        return `${(bytesPerSec / 1024 ** i).toFixed(2)} ${units[i]}`;
    },

    formatETA(torrent) {
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

    formatSize(bytes) {
        if (!bytes) return "0 B";

        const units = ["B", "KB", "MB", "GB", "TB"];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));

        return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
    },

    infoDetails(torrent) {
        if (!torrent) 
            return document.createElement("div"); 

        const list = document.createElement("ul");

        const keys = ["status", "hashString", "magnetLink", "pieceCount", "errorString"];

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
                    cell.appendChild(link);

                    break;

                case "pieceCount":
                    if (value)
                        cell.textContent = `Pieces: ${value} x ${this.formatSize(torrent.pieceSize)}`;
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
    },

    filesDetails(files) {
        if (!files?.length) 
            return document.createElement("div"); 

        // files frame
        const fs_files = document.createElement("fieldset");

        // files frame label
        const fs_files_lable = document.createElement("legend");
        fs_files_lable.textContent = `Files: ${files.length}`
        fs_files.appendChild(fs_files_lable);

        // files fields
        const files_table_cols = ["name", "progress", "size", "have", "left"];

        // files table
        const files_table = document.createElement("table");
        files_table.className = "compact-table";

        // files table header
        files_table_cols.forEach((item) => {
            const th = document.createElement("th");
            th.textContent = item;
            th.style.whiteSpace = 'nowrap'
            files_table.appendChild(th);
        });

        // files table data
        files.forEach((file, index) => {
            const tr = document.createElement("tr");

            files_table_cols.forEach(key => {
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
                        cell.textContent = this.formatSize(file.length);
                        break;
                    case "have":
                        cell.textContent = file.bytesCompleted ? this.formatSize(file.bytesCompleted) : "";
                        break;
                    case "left":
                        cell.textContent = (file.length - file.bytesCompleted) ? this.formatSize(file.length - file.bytesCompleted) : "";
                        break;
                }

                if (key !== "name")
                    cell.style.whiteSpace = 'nowrap'

                tr.appendChild(cell);
            });

			if (index % 2)
				tr.style.backgroundColor = "#ebebeb";

            files_table.appendChild(tr);
        });

        fs_files.appendChild(files_table);

        return fs_files
    },

    trackerDetails(trackerStats) {
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

			if (index % 2)
				tr.style.backgroundColor = "#ebebeb";
            
            table.appendChild(tr);
        });

        fs.appendChild(table);

        return fs
    },

    peerDetails(peers) {
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
                        cell.textContent = peer.rateToClient ? this.formatBytes(peer.rateToClient) : "";
                        break;

                    case "speedUp":
                        cell.textContent = peer.rateToPeer ? this.formatBytes(peer.rateToPeer) : "";
                        break;
                }

                tr.appendChild(cell);
            });

			if (index % 2)
				tr.style.backgroundColor = "#ebebeb";

            table.appendChild(tr);
        });

        fs.appendChild(table);

        return fs
    },

    torrentTable(torrents) {
        if (!torrents?.length) 
            return {
                "table": document.createElement("div"),
                "allDw": 0,
                "allUp": 0,
                "allSize": 0
            } 

        let allDw = allUp = allSize = 0;

		const buttons = [
			{ className: "tr-start", text: "▶️", title: "Start" },
			{ className: "tr-pause", text: "⏸️", title: "Pause" },
			{ className: "tr-reannounce", text: "🔄", title: "Reannounce" },
			{ className: "tr-delete", text: "❌", title: "Delete torrent"},
			{ className: "tr-deletefiles", text: "🗑️", title: "Delete torrent and files"}
		];

		const buttonsAll = [
			{ className: "tr-start-all", text: "▶️", title: "Start all" },
			{ className: "tr-pause-all", text: "⏸️", title: "Pause all" },
			{ className: "tr-reannounce-all", text: "🔄", title: "Reannounce all" }
		];

		const table_cols = ["id", "name", "progress", "S / L", "speedDw", "speedUp", "size", "have", "eta", "actions"];

		const table = document.createElement("table");
		table.className = "compact-table";

		table_cols.forEach((item) => {
			const th = document.createElement("th");
			th.textContent = item;
			th.style.whiteSpace = 'nowrap'
			table.appendChild(th);
		});

		torrents.forEach((torrent, index) => {
			const tr = document.createElement("tr");
			const is_magnet = torrent.metadataPercentComplete < 1
			
			table_cols.forEach(key => {
				const cell = document.createElement("td");

				switch (key) {
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

						pr_color = "#E5E7EB"
						pr_lable = is_magnet ? '🧲' : `${percent}%`;
						switch (torrent.status) {
							case 4:
								pr_color = "#44abff"; // downloading
								if (!torrent.rateDownload && !is_magnet) {
									pr_color = "#0072cf"; // stalled
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
						cell.textContent = torrent.rateDownload ? utils.formatBytes(torrent.rateDownload) : "";
						allDw += torrent.rateDownload;
						break;

					case "speedUp":
						cell.textContent = torrent.rateUpload ? utils.formatBytes(torrent.rateUpload) : "";
						allUp += torrent.rateUpload;
						break;

					case "size":
						cell.textContent = torrent.totalSize ? utils.formatSize(torrent.totalSize) : "";
						allSize += torrent.totalSize
						break;

					case "have":
						cell.textContent = (torrent.haveValid === 0 || torrent.haveValid === torrent.totalSize) ? "" : utils.formatSize(torrent.haveValid);
						break;

					case "eta":
						cell.textContent = utils.formatETA(torrent);
						break;

					case "actions":
						cell.className = "buttons-cell";

						const buttonRow = document.createElement("div");
						buttonRow.className = "button-row";

						buttons.forEach(({className, text, title}) => {
							const button = document.createElement("button");
							button.className = className;
							button.textContent = text;
							button.dataset.id = torrent.id;
							button.title = title;

							buttonRow.appendChild(button);
						});

						cell.appendChild(buttonRow);
						break;
				}

				if (key !== "name")
					cell.style.whiteSpace = 'nowrap'

				tr.appendChild(cell);
			});

			if (index % 2)
				tr.style.backgroundColor = "#ebebeb";

            tr.dataset.id = torrent.id
            tr.classList.add("torrent-row");

			table.appendChild(tr);
		});

		// bottom row
		const tr = document.createElement("tr");
		table_cols.forEach(key => {
			const cell = document.createElement("td");

			switch (key) {
				case "speedDw":
					cell.textContent = allDw ? utils.formatBytes(allDw) : "";
					cell.style.fontWeight = "bold";
					break;

				case "speedUp":
					cell.textContent = allUp ? utils.formatBytes(allUp) : "";
					cell.style.fontWeight = "bold";
					break;

				case "size":
					cell.textContent = allSize ? utils.formatSize(allSize) : "";
					cell.style.fontWeight = "bold";
					break;

				case "actions":
					cell.className = "buttons-cell";

					const buttonRow = document.createElement("div");
					buttonRow.className = "button-row";

					buttonsAll.forEach(({className, text, title}) => {
						const button = document.createElement("button");
						button.className = className;
						button.textContent = text;
						button.title = title;

						buttonRow.appendChild(button);
					});

					cell.appendChild(buttonRow);
					break;
			}
			
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
    }
};