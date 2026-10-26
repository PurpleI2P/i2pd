let torrents = []; // torrents table data
let details_id = null; // torrent id for details table

const el_torrents = document.getElementById("div-torrents")

const el_fs_error = document.getElementById("fs-error")
const el_err_string = document.getElementById("err-string");
const el_err_details = document.getElementById("err-details")

const el_details = document.getElementById("div-details")
const el_torrentfile = document.getElementById("torrent-file")

const el_dht_stats_list = document.getElementById("dht-stats-list")
const el_fs_dht_stats = document.getElementById("fs-dht-stats");

const el_session_stats_list = document.getElementById("session-stats-list")
const el_fs_session_stats = document.getElementById("fs-session-stats")

refreshTable(); 
refreshDhtStats();
refreshSessionStats();

setInterval(async () => {
    await Promise.all([
        refreshDhtStats(),
        refreshSessionStats()
    ]);
}, 10000);

setInterval(async () => refreshTable(), 5000);

function jsLoaded() {
	return window.rpc && window.utils
}

function setError(err, err_details) {
	el_err_string.textContent = err || "";
	el_err_details.textContent = err_details || "";
	el_fs_error.style.display = "block";
	if (err_details)
		console.log(err_details)
}

function clearError() {
	setError("", "")
	el_fs_error.style.display = "none";
}

async function addMagnet() {
	const name = prompt("enter the magnet link:", "");

	if (name === null) 
		return;

	const r = await rpc.addTorrentByMagnet(name)
	if (r.result !== "success")
		alert(r.result);
	refreshTable();
}

async function stopAll() {
  	if (!jsLoaded()) 
		return;

	const r = await rpc.torrentStop()
	if (r.result !== "success")
		alert(r.result);
}

async function startAll() {
  	if (!jsLoaded()) 
		return;

	const r = await rpc.torrentStart()
	if (r.result !== "success")
		alert(r.result);
}

async function removeTorrent(id) {
  	if (!jsLoaded()) 
		return;

	const confirmed = confirm(`remove the torrent with id=${id} ?`);
	if (confirmed)
		await rpc.removeTorrent(Number(id), false);
};

async function removeTorrentAndFiles(id) {
  	if (!jsLoaded()) 
		return;

	const confirmed = confirm(`remove the torrent AND FILES with id=${id} ?`);
	if (confirmed)
		await rpc.removeTorrent(Number(id), true);
};

// add local torrent file
el_torrentfile.onchange = (e) => {
  	if (!jsLoaded()) 
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
		await rpc.addTorrent(b64);
		e.target.value = "";
	};
	reader.readAsArrayBuffer(file);

	refreshTable();
};

async function refreshSessionStats() {
  	if (!jsLoaded()) 
		return;

	const r = await rpc.sessionStats();
	
	if (!r?.arguments?.["current-stats"])
		return (el_fs_session_stats.style.display = "none")

	result = r.arguments["current-stats"]

	const list = document.createElement("div");

	const labels = {
		downloadedBytes: "Downloaded",
		uploadedBytes: "Uploaded"
	};

	Object.keys(result).forEach(key => {
		if (key in labels) {
			const cell = document.createElement("li");
			cell.textContent = `${labels[key]}: ${utils.formatSize(result[key])}`;
			list.appendChild(cell);
		}
	});

	el_session_stats_list.replaceChildren(list)
	el_fs_session_stats.style.display = "block";
}

async function refreshDhtStats() {
  	if (!jsLoaded()) 
		return;

	const r = await rpc.dhtStats();
	
	if (!r?.arguments)
		return (el_fs_dht_stats.style.display = "none")

	result = r.arguments

	const list = document.createElement("div");

	const labels = {
		supported: "Enabled",
		numNodes: "Nodes",
		numBuckets: "Buckets",
		numTorrents: "Torrents",
		numHeardFrom: "Heard from",
		numFailedPeers: "Failed peers"
	};

	Object.keys(result).forEach(key => {
		if (key in labels) {
			const cell = document.createElement("li");
			cell.textContent = `${labels[key]}: ${result[key]}`;
			list.appendChild(cell);
		}
	});

	el_dht_stats_list.replaceChildren(list)
	el_fs_dht_stats.style.display = "block";
}

el_torrents.addEventListener("click", async (event) => {
    if (!jsLoaded()) 
		return;

    const torrentActions = {
        ".tr-start": async (id) => rpc.torrentStart([id]),
        ".tr-pause": async (id) => rpc.torrentStop([id]),
        ".tr-delete": async (id) => removeTorrent([id]),
        ".tr-deletefiles": async (id) => removeTorrentAndFiles([id]),
        ".tr-reannounce": async (id) => rpc.torrentReannounce([id]),
		
        ".tr-start-all": async () => startAll(),
        ".tr-pause-all": async () => stopAll(),
        ".tr-reannounce-all": async () => rpc.torrentReannounce()
    };

    const button = event.target.closest(Object.keys(torrentActions).join(","));

    if (button && el_torrents.contains(button)) {
        const action = Object.keys(torrentActions).find(selector =>
            button.matches(selector)
        );

        if (!action) return;

        const id = Number(button.dataset.id || 0);
        if (!Number.isSafeInteger(id)) return;

        await torrentActions[action](id);
        await refreshTable();
        return;
    }

    const row = event.target.closest("tr");
    if (!row || !el_torrents.contains(row)) return;

    const id = Number(row.dataset.id || 0);
    if (!Number.isSafeInteger(id) || id <= 0) return;

    await openTorrentDetails([id]);
});

// refresh table with torrents
async function refreshTable() {
	if (!window.rpc)
		return setError('failed to load rpc.js', "")

	if (!window.utils)
		return setError('failed to load utils.js', "")

	try {
		const r = await rpc.torrentGet();

		if (r?.result !== "success")
			return setError('failed response', r)

		torrents = r.arguments.torrents;

		if (torrents.length === 0) {
			el_torrents.replaceChildren();
			clearError();
			return;
		}

		tr_table = utils.torrentTable(torrents)

		const fs = document.createElement("fieldset");

		const lable = document.createElement("legend");
		lable.textContent = `Torrents: ${torrents.length}`
		fs.append(lable, tr_table.table);

		el_torrents.replaceChildren(fs);

		document.title = `↓${utils.formatBytes(tr_table.allDw)} ↑${utils.formatBytes(tr_table.allUp)}`;

		if (details_id !== null)
			openTorrentDetails(details_id)

		clearError()

	} catch (err) {
		setError('failed to update torrents table', err)
	}
}

function openTorrentDetails(id) {
  	if (!jsLoaded()) 
		return;

	const torrent = torrents.find(t => t.id == id);
	if (!torrent) 
		return;

	details_id = torrent.id

	// main frame
	const fs = document.createElement("fieldset");

	// main frame label
	const content = document.createElement("div");
	content.style.display = "flex";
	content.style.justifyContent = "space-between";
	content.style.width = "100%";

	const lable = document.createElement("span");
	lable.textContent = `#${torrent.id}: ${torrent.name} `;

	const close_link = document.createElement("href");
	close_link.textContent = "Close";
	close_link.style.color = "#0000ee";
	close_link.style.cursor = "pointer";
	close_link.style.textDecoration = "underline";
	close_link.onclick = closeTorrentDetails;
	content.append(lable, close_link);

	const legend = document.createElement("legend");
	legend.style.width = "100%";
	legend.appendChild(content);

	fs.prepend(legend);

	fs.append(
		utils.infoDetails(torrent),
		utils.peerDetails(torrent.peers),
		utils.trackerDetails(torrent.trackerStats),
		utils.filesDetails(torrent.files)
	);

	el_details.replaceChildren(fs);
};

function closeTorrentDetails() {
	details_id = null;
	el_details.replaceChildren();
};