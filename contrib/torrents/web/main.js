let torrents_data = []; // torrents table data
let details_timer = null;

const el_torrents = document.getElementById("torrents")

const el_fs_error = document.getElementById("fs-error")
const el_err_string = document.getElementById("err-string");
const el_err_details = document.getElementById("err-details")

const el_details = document.getElementById("details")
const el_torrentf = document.getElementById("torrentf")

const el_dht_stats_list = document.getElementById("dht-stats-list")
const el_fs_dht_stats = document.getElementById("fs-dht-stats");

const el_session_stats_list = document.getElementById("session-stats-list")
const el_fs_session_stats = document.getElementById("fs-session-stats")


refreshTable(); 
setInterval(async () => refreshTable(), 5000);

refreshSessionStats();
setInterval(async () => refreshSessionStats(), 10000);

refreshDhtStats();
setInterval(async () => refreshDhtStats(), 60000);


function setError(err, err_details) {
	el_err_string.textContent = err || "";
	el_err_details.textContent = err_details || "";
	el_fs_error.style.display = "block";
	if (err_details)
		console.log(err_details)
}

function clearError() {
	this.setError("", "")
	el_fs_error.style.display = "none";
}

function startDetailsTimer(id) {
	stopDetailsTimer();

	details_timer = setInterval(async () => {
		await openTorrentDetails([id]);
	}, 2500);
}

function stopDetailsTimer() {
	clearInterval(details_timer);
	details_timer = null;
}

function formatBytes(bytesPerSec) {
  if (!Number.isFinite(bytesPerSec) || bytesPerSec <= 0) {
    return "0 B/s";
  }

  const units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
  const i = Math.min(
    Math.floor(Math.log(bytesPerSec) / Math.log(1024)),
    units.length - 1
  );

  return `${(bytesPerSec / 1024 ** i).toFixed(2)} ${units[i]}`;
}

function formatETA(tr_obj) {
  const speed = tr_obj.rateDownload || 0;
  const remaining = (tr_obj.totalSize || 0) * (1 - (tr_obj.percentDone || 0));

  if (speed <= 0) return "";

  const seconds = remaining / speed;

  if (seconds < 60) {
    return `${Math.ceil(seconds)} sec`;
  }

  if (seconds < 3600) {
    return `${(seconds / 60).toFixed(1)} min`;
  }

  if (seconds < 86400) {
    return `${(seconds / 3600).toFixed(1)} h`;
  }

  return `${(seconds / 86400).toFixed(1)} days`;
}

function formatSize(bytes) {
  if (!bytes) return "0 B";

  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));

  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

async function addMagnet() {
	const name = prompt("enter the magnet link:", "");

	if (name !== null) {
		const r = await window.rpc.addTorrentByMagnet(name)
		if (r.result !== "success")
			alert(r.result);
		refreshTable();
	}
}

async function stopAll() {
  	if (!window.rpc) 
		return;

	const r = await window.rpc.torrentStop()
	if (r.result !== "success")
		alert(r.result);
}

async function startAll() {
  	if (!window.rpc) 
		return;

	const r = await window.rpc.torrentStart()
	if (r.result !== "success")
		alert(r.result);
}

window.removeTorrent = async (id) => {
  	if (!window.rpc) 
		return;

	const confirmed = confirm(`remove the torrent with id=${id} ?`);
	if (confirmed)
		await window.rpc.removeTorrent(Number(id), false);
};

window.removeTorrentAndFiles = async (id) => {
  	if (!window.rpc) 
		return;

	const confirmed = confirm(`remove the torrent AND FILES with id=${id} ?`);
	if (confirmed)
		await window.rpc.removeTorrent(Number(id), true);
};

// buttons in torrents table
torrents.addEventListener("click", async (event) => {
  if (!window.rpc) 
	return;

  // action buttons for torrents
  const torrentActions = {
    ".tr-details": async (id) => openTorrentDetails([id]),
    ".tr-start": async (id) => window.rpc.torrentStart([id]),
    ".tr-pause": async (id) => window.rpc.torrentStop([id]),
    ".tr-delete": async (id) => removeTorrent([id]),
    ".tr-deletefiles": async (id) => removeTorrentAndFiles([id]),
    ".tr-reannounce": async (id) => window.rpc.torrentReannounce([id]),

    ".tr-start-all": async () => startAll(),
    ".tr-pause-all": async () => stopAll(),
    ".tr-reannounce-all": async (id) => window.rpc.torrentReannounce()
  };

  const button = event.target.closest(
    Object.keys(torrentActions).join(",")
  );

  if (!button || !torrents.contains(button)) 
	return;

  const action = Object.keys(torrentActions).find(
    (selector) => button.matches(selector)
  );

  if (!action) 
	return;

  const id = Number(button.dataset.id || 0);
  if (!Number.isSafeInteger(id))
    return;

  await torrentActions[action](id);
  await refreshTable();
});

async function refreshSessionStats() {
  	if (!window.rpc) 
		return;

	const r = await window.rpc.sessionStats();
	
	if (!r)
		return (el_fs_session_stats.style.display = "none")

	session_data = r.arguments["current-stats"]
	//console.log('session', session_data)

	const session_list = document.createElement("div");

	const session_fields = ["downloadedBytes", "uploadedBytes"];

	Object.keys(session_data).forEach(key => {
		const cell = document.createElement("li");
		const value = session_data[key];

		switch (key) {
			case "downloadedBytes":
				cell.textContent = `Downloaded: ${formatSize(value)}`;
				break;

			case "uploadedBytes":
				cell.textContent = `Uploaded: ${formatSize(value)}`;
				break;
		}

		if (cell.textContent)
			session_list.appendChild(cell);
	});

	el_session_stats_list.replaceChildren(session_list)
	el_fs_session_stats.style.display = "block";
}

async function refreshDhtStats() {
  	if (!window.rpc) 
		return;

	const r = await window.rpc.dhtStats();
	
	if (!r)
		return (el_fs_dht_stats.style.display = "none")

	dht_data = r.arguments
	//console.log('dht', dht_data)

	const dht_list = document.createElement("div");

	const dht_fields = ["supported", "numNodes", "numBuckets", "numTorrents", "numHeardFrom", "numFailedPeers"];

	Object.keys(dht_data).forEach(key => {
		const cell = document.createElement("li");
		const value = dht_data[key];

		switch (key) {
			case "supported":
				cell.textContent = `Enabled: ${value}`;
				break;

			case "numNodes":
				cell.textContent = `Nodes: ${value}`;
				break;

			case "numBuckets":
				cell.textContent = `Buckets: ${value}`;
				break;

			case "numTorrents":
				cell.textContent = `Torrents: ${value}`;
				break;

			case "numHeardFrom":
				cell.textContent = `Heard from: ${value}`;
				break;

			case "numFailedPeers":
				cell.textContent = `Failed peers: ${value}`;
				break;
		}

		if (cell.textContent)
			dht_list.appendChild(cell);
	});

	el_dht_stats_list.replaceChildren(dht_list)
	el_fs_dht_stats.style.display = "block";
}

// refresh table with torrents
async function refreshTable() {
	if (!window.rpc)
		return setError('failed to load rpc.js', "")

	try {
		const r = await window.rpc.torrentGet();

		if (r?.result !== "success")
			return setError('failed response', r)

		torrents_data = r.arguments.torrents;

		if (torrents_data.length === 0) {
			el_torrents.replaceChildren();
			clearError();
			return;
		}

		const table_cols = ["id", "name", "progress", "S / L", "speedDw", "speedUp", "size", "have", "eta", "actions"];

		const table = document.createElement("table");
		table.className = "compact-table";

		table_cols.forEach((item) => {
			const th = document.createElement("th");
			th.textContent = item;
			table.appendChild(th);
		});

		let allDw = allUp = allSize = 0;

		torrents_data.forEach(tr_obj => {
			const tr = document.createElement("tr");

			table_cols.forEach(key => {
				const cell = document.createElement("td");
				const value = tr_obj[key];

				switch (key) {
					case "id":
						cell.textContent = value ?? -1;
						break;

					case "name":
						cell.textContent = value ?? "null";

						if (tr_obj.errorString) {
							cell.style.fontWeight = "bold";
							cell.style.color = "#ff3333";
						}

						break;

					case "progress": {
						cell.className = "progress-cell";

						const percent = Math.max(0, Math.min(100, (tr_obj.percentDone * 100).toFixed(1)))

						const progressBar = document.createElement("div");
						progressBar.className = "progress-bar";

						const progressFill = document.createElement("div");
						progressFill.className = "progress-fill";
						progressFill.style.width = `${percent}%`;

						const is_magnet = tr_obj.metadataPercentComplete < 1
						pr_color = "#E5E7EB"
						pr_lable = is_magnet ? '🧲' : `${percent}%`;
						switch (tr_obj.status) {
							case 4:
								pr_color = "#44abff"; // downloading
								if (!tr_obj.rateDownload && !is_magnet) {
									pr_color = "#0072cf"; // stalled
									pr_lable += ', stalled'
								}
								break;
							case 6:
								pr_color = "#00FF5A"; // seeding
								break;
							case 0:
								if (tr_obj.percentDone < 1) {
									pr_color = "#ffd000"; // paused
									pr_lable += ', paused'
								}
						}

						progressFill.style.backgroundColor = pr_color;

						progressBar.appendChild(progressFill);

						const progressText = document.createElement("div");
						progressText.className = "progress-text";
						progressText.textContent = pr_lable


						cell.append(progressBar, progressText);
						break;
					}

					case "S / L":
						seeders = leechers = 0

						tr_obj.peers.forEach(peer => {
							if (peer.progress !== 0)
								peer.progress === 1 ? seeders++ : leechers++
						});

						if (tr_obj.status === 6)
							cell.textContent = leechers || "" // we are seeding
						else if (seeders || leechers)
							cell.textContent = `${seeders} / ${leechers}`; // we are leeching

						break;

					case "speedDw":
						cell.textContent = tr_obj.rateDownload ? formatBytes(tr_obj.rateDownload) : "";
						allDw += tr_obj.rateDownload;
						break;

					case "speedUp":
						cell.textContent = tr_obj.rateUpload ? formatBytes(tr_obj.rateUpload) : "";
						allUp += tr_obj.rateUpload;
						break;

					case "size":
						cell.textContent = tr_obj.totalSize ? formatSize(tr_obj.totalSize) : "";
						allSize += tr_obj.totalSize
						break;

					case "have":
						cell.textContent = (tr_obj.haveValid === 0 || tr_obj.haveValid === tr_obj.totalSize) ? "" : formatSize(tr_obj.haveValid);
						break;

					case "eta":
						cell.textContent = formatETA(tr_obj);
						break;

					case "actions":
						cell.className = "buttons-cell";

						const buttonRow = document.createElement("div");
						buttonRow.className = "button-row";

						const torrentButtons = [
							{ className: "tr-details", text: "ℹ️", title: "Details" },
							{ className: "tr-start", text: "▶️", title: "Start" },
							{ className: "tr-pause", text: "⏸️", title: "Pause" },
							{ className: "tr-reannounce", text: "🔄", title: "Reannounce" },
							{ className: "tr-delete", text: "❌", title: "Delete torrent"},
							{ className: "tr-deletefiles", text: "🗑️", title: "Delete torrent and files"}
						];

						torrentButtons.forEach(({className,	text, title}) => {
							const button = document.createElement("button");

							button.className = className;
							button.textContent = text;
							button.dataset.id = tr_obj.id;
							button.title = title;

							buttonRow.appendChild(button);
						});

						cell.appendChild(buttonRow);
						break;
				}

				tr.appendChild(cell);
			});

			table.appendChild(tr);
		});

		// bottom row
		const tr = document.createElement("tr");
		table_cols.forEach(key => {
			const cell = document.createElement("td");

			switch (key) {
				case "speedDw":
					cell.textContent = allDw ? formatBytes(allDw) : "";
					cell.style.fontWeight = "bold";
					break;

				case "speedUp":
					cell.textContent = allUp ? formatBytes(allUp) : "";
					cell.style.fontWeight = "bold";
					break;

				case "size":
					cell.textContent = allSize ? formatSize(allSize) : "";
					cell.style.fontWeight = "bold";
					break;

				case "actions":
					cell.className = "buttons-cell";

					const buttonRow = document.createElement("div");
					buttonRow.className = "button-row";

					const globalButtons = [
						{ className: "tr-start-all", text: "▶️", title: "Start all" },
						{ className: "tr-pause-all", text: "⏸️", title: "Pause all" },
						{ className: "tr-reannounce-all", text: "🔄", title: "Reannounce all" },
					];

					globalButtons.forEach(({className, text, title}) => {
						const button = document.createElement("button");

						button.className = className;
						button.textContent = text;
						button.title = title;

						buttonRow.appendChild(button);
					});

					cell.appendChild(buttonRow);
					break;
			}

			tr.appendChild(cell);
		});

		table.appendChild(tr);

		// main frame label
		const fs_torrents = document.createElement("fieldset");

		const fs_torrents_lable = document.createElement("legend");
		fs_torrents_lable.textContent = `Torrents: ${torrents_data.length}`
		fs_torrents.appendChild(fs_torrents_lable);

		fs_torrents.appendChild(table);

		document.title = `↓${formatBytes(allDw)} ↑${formatBytes(allUp)}`;

		torrents.replaceChildren(fs_torrents);

		clearError()

	} catch (err) {
		setError('failed to update torrents table', err)
	}
}

// add local torrent file
el_torrentf.onchange = (e) => {
	if (!window.rpc)
		return;

	const file = e.target.files[0];
	if (!file) return;

	const reader = new FileReader();
	reader.onload = async () => {
		const bytes = new Uint8Array(reader.result);
		let binary = "";
		for (let i = 0; i < bytes.byteLength; i++) {
			binary += String.fromCharCode(bytes[i]);
		}
		const b64 = btoa(binary);
		if (window.rpc) await window.rpc.addTorrent(b64);
		e.target.value = "";
	};
	reader.readAsArrayBuffer(file);
};

// close torrent details
window.closeDetailsModal = () => {
  el_details.replaceChildren();
  stopDetailsTimer();
};

// open torrent details
window.openTorrentDetails = (tr_id) => {
  	if (!window.rpc) 
		return;

	const torrent = torrents_data.find((t) => t.id == tr_id);
	if (!torrent) return;

	// main frame
	const fs_main = document.createElement("fieldset");

	// main frame label
	const legend = document.createElement("legend");
	const content = document.createElement("div");
	const lable = document.createElement("span");
	const close_link = document.createElement("href");

	lable.textContent = `#${torrent.id}: ${torrent.name} `;
	close_link.textContent = "Close";
	close_link.href = "#";
	close_link.style.color = "#0000ee";
	close_link.style.cursor = "pointer";
	close_link.style.textDecoration = "underline";
	close_link.onclick = closeDetailsModal;

	legend.style.width = "100%";

	content.style.display = "flex";
	content.style.justifyContent = "space-between";
	content.style.width = "100%";

	content.append(lable, close_link);
	legend.appendChild(content);

	fs_main.prepend(legend);

	
	const info_list = document.createElement("ul");

	const info_cols = ["status", "hashString", "magnetLink", "pieces", "errorString"];

	info_cols.forEach(key => {
		const cell = document.createElement("li");
		const value = torrent[key];

		switch (key) {
			case "hashString":
				cell.textContent = `Hash: ${value || "None"}`;
				break;

			case "magnetLink":
				cell.textContent = `Magnet: `;

				const href = value.length > 60 ? value.slice(0, 60) + '...' : url;
				const link = document.createElement('a');

				link.textContent = href;
				link.href = value;

				cell.appendChild(link);
				break;

			case "pieces":
				if (torrent.pieceCount) {
					cell.textContent = `Pieces: ${torrent.pieceCount} x ${formatSize(torrent.pieceSize)}`;
				}
				break;

			case "status":
				tr_status = [
					"Stopped",
					"QueuedToVerifyLocalData",
					"VerifyingLocalData",
					"QueuedToDownload",
					"Downloading",
					"QueuedToSeed",
					"Seeding"
				];

				if (torrent.status < tr_status.length) {
					cell.textContent = `Status: ${tr_status[torrent.status]}`;
				}
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
			info_list.appendChild(cell);
	});

	fs_main.appendChild(info_list);

	// PEERS
	if (torrent.peers.length) {

		// peers frame
		const fs_peers = document.createElement("fieldset");

		// peers frame label
		const fs_peers_lable = document.createElement("legend");
		fs_peers_lable.textContent = `Peers: ${torrent.peers.length}`
		fs_peers.appendChild(fs_peers_lable);

		// peer fields
		const peer_table_cols = ["address", "client", "flags", "progress", "speedDw", "speedUp"];

		// peer table
		const peer_table = document.createElement("table");
		peer_table.className = "compact-table";

		// peer table header
		peer_table_cols.forEach((item) => {
			const th = document.createElement("th");
			th.textContent = item;
			peer_table.appendChild(th);
		});

		// peer table data
		torrent.peers.forEach(peer => {
			const tr = document.createElement("tr");

			peer_table_cols.forEach(key => {
				const cell = document.createElement("td");
				const value = peer[key];

				switch (key) {
					case "address":
						cell.textContent = value;
						break;

					case "client":
						cell.textContent = peer.clientName;
						break;

					case "flags":
						cell.textContent = peer.flagStr;
						break;

					case "progress":
						cell.className = "progress-cell";

						const percent = Math.max(0, Math.min(100, (peer.progress * 100).toFixed(1)))

						const progressBar = document.createElement("div");
						progressBar.className = "progress-bar";

						const progressFill = document.createElement("div");
						progressFill.className = "progress-fill";
						progressFill.style.width = `${percent}%`;
						progressFill.style.backgroundColor = peer.progress === 1 ? "#00FF5A" : "#4DAFFF";

						progressBar.appendChild(progressFill);

						const progressText = document.createElement("div");
						progressText.className = "progress-text";
						progressText.textContent = `${percent}%`;

						cell.append(progressBar, progressText);
						break;

					case "speedDw":
						cell.textContent = peer.rateToClient ? formatBytes(peer.rateToClient) : "";
						break;

					case "speedUp":
						cell.textContent = peer.rateToPeer ? formatBytes(peer.rateToPeer) : "";
						break;
				}

				tr.appendChild(cell);
			});

			peer_table.appendChild(tr);
		});

		fs_peers.appendChild(peer_table);

		fs_main.appendChild(fs_peers);
	} // peers

	// TRACKERS
	if (torrent.trackerStats.length) {

		// trackers frame
		const fs_trackers = document.createElement("fieldset");

		// trackers frame label
		const fs_trackers_lable = document.createElement("legend");
		fs_trackers_lable.textContent = `Trackers: ${torrent.trackerStats.length}`
		fs_trackers.appendChild(fs_trackers_lable);

		// trackers fields
		const trackers_table_cols = ["id", "announce", "peers", "seeders", "leechers", "lastAnnounceResult", "lastAnnounceTime", "nextAnnounceTime"];

		// trackers table
		const trackers_table = document.createElement("table");
		trackers_table.className = "compact-table";

		// trackers table header
		trackers_table_cols.forEach((item) => {
			const th = document.createElement("th");
			th.textContent = item;
			trackers_table.appendChild(th);
		});

		// peer table data
		torrent.trackerStats.forEach(tracker => {
			const tr = document.createElement("tr");

			trackers_table_cols.forEach(key => {
				const cell = document.createElement("td");
				const value = tracker[key];

				switch (key) {
					case "id":
						cell.textContent = value;
						break;
					case "announce":
						cell.textContent = value;
						break;
					case "seeders":
						cell.textContent = tracker.seederCount || 0;
						break;
					case "leechers":
						cell.textContent = tracker.leecherCount >= 0 ? tracker.leecherCount : '?'; // todo: big value?
						break;
					case "peers":
						cell.textContent = tracker.lastAnnouncePeerCount || 0;
						break;
					case "lastAnnounceResult":
						cell.textContent = value;
						break;
					case "lastAnnounceTime":
						cell.textContent = `${new Date(tracker.lastAnnounceTime * 1000).toLocaleString()}`;
						break;
					case "nextAnnounceTime":
						cell.textContent = `${new Date(tracker.nextAnnounceTime * 1000).toLocaleString()}`;
						break;
				}

				tr.appendChild(cell);
			});

			trackers_table.appendChild(tr);
		});

		fs_trackers.appendChild(trackers_table);

		fs_main.appendChild(fs_trackers);
	} // trackers

	// FILES
	if (torrent.files.length) {

		// files frame
		const fs_files = document.createElement("fieldset");

		// files frame label
		const fs_files_lable = document.createElement("legend");
		fs_files_lable.textContent = `Files: ${torrent.files.length}`
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
			files_table.appendChild(th);
		});

		// files table data
		torrent.files.forEach(file => {
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
							Math.min(1, Math.max(0, file.bytesCompleted / file.length)) :
							0;

						const percent = Math.max(0, Math.min(100, (progress * 100).toFixed(1)))

						const progressBar = document.createElement("div");
						progressBar.className = "progress-bar";

						const progressFill = document.createElement("div");
						progressFill.className = "progress-fill";
						progressFill.style.width = `${percent}%`;
						progressFill.style.backgroundColor = progress === 1 ? "#00FF5A" : "#4DAFFF";

						progressBar.appendChild(progressFill);

						const progressText = document.createElement("div");
						progressText.className = "progress-text";
						progressText.textContent = `${percent}%`;

						cell.append(progressBar, progressText);
						break;
					case "size":
						cell.textContent = formatSize(file.length);
						break;
					case "have":
						cell.textContent = file.bytesCompleted ? formatSize(file.bytesCompleted) : "";
						break;
					case "left":
						cell.textContent = file.length - file.bytesCompleted ? formatSize(file.length - file.bytesCompleted) : "";
						break;
				}

				tr.appendChild(cell);
			});

			files_table.appendChild(tr);
		});

		fs_files.appendChild(files_table);

		fs_main.appendChild(fs_files);
	}

	el_details.replaceChildren(fs_main);

	startDetailsTimer(tr_id);
};