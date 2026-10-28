// torrents from torrent-get 
let torrents = [];

// torrent id for openTorrentDetails() selector
let selected_torrent = 0;

// selection of torrents from refreshTable() for actions
let selected_torrents = [];

// update delays
let torrents_delay = 5*1000 // 5 sec
let stats_delay = 10*1000 // 10 sec

const el = {
    torrents: document.getElementById("div-torrents"),

    fs_error: document.getElementById("fs-error"),
    err_string: document.getElementById("err-string"),
    err_details: document.getElementById("err-details"),

    details: document.getElementById("div-details"),
    torrent_file: document.getElementById("torrent-file"),

    dht_stats_list: document.getElementById("dht-stats-list"),
    fs_dht_stats: document.getElementById("fs-dht-stats"),

    session_stats_list: document.getElementById("session-stats-list"),
    fs_session_stats: document.getElementById("fs-session-stats"),

    torrent_rcm: document.getElementById("torrent-rcm")
};

function now_ts() { return Math.floor(Date.now() / 1000) };
let exh_ts = 0;

// display errors
function vis_exh(err = "", err_details = "") {
	const is_blank = !(err || err_details);

	if (is_blank && now_ts() - exh_ts < 30)
		return;

	exh_ts = now_ts()

	el.err_string.textContent = err;
	el.err_details.textContent = err_details;
	el.fs_error.style.display = is_blank ? "none" : "block";
	if (!is_blank) {
		console.log(err)
		console.log(err_details)
	}
}

// catch js errors
window.addEventListener("error", event => {
    vis_exh(
		`[js] ${event.message}`, 
		`${event.filename}@${event.lineno}:${event.colno}: ${event.error}`
	);
});

// catch async errors
window.addEventListener("unhandledrejection", event => {
	const error = event.reason;
    vis_exh(
		`[promise] ${error}`, 
		error?.stack
	)
});

// checking for loaded js files
function js() {
	return Boolean(window.rpc && window.util)
}

refreshTable(); 
refreshDhtStats();
refreshSessionStats();

setInterval(async () => {
    await Promise.all([
        refreshDhtStats(),
        refreshSessionStats()
    ]);
}, stats_delay);

setInterval(
	async () => refreshTable(), 
	torrents_delay
);

async function addMagnet() {
	const input = prompt("enter the magnet link:", "");

	if (!input) 
		return;

	const magnets = input.split(" ");

    magnets.forEach(async magnet => {
		const r = await rpc.addTorrentByMagnet(magnet)
		if (magnets.length === 1 && r.result !== "success")
			alert(r.result);
    });

	await refreshTable();
}

async function torrentRemove(ids = [], withFiles = false) {
  	if (!js() || !ids.length) return;

	let warn = `remove the following torrents${withFiles ? ' WITH FILES' : ""}?\n\n`

	const objs = util.sel.idsToObj(ids)

    objs.forEach(obj => {
		warn += `#${obj.id} | ${obj.name}\n`
    });

	const confirmed = confirm(warn);
	if (!confirmed)
		return;

	await rpc.torrentRemove(ids, withFiles);
	await refreshTable({
		closeDetails:
			selected_torrent === ids[0] || util.sel.isSelected(selected_torrent)
	});
};

// add local torrent files
el.torrent_file.onchange = async (e) => {
	if (!js()) return;

	const input = e.target;
    const files = [...input.files];

    if (!files || !files.length)
		return;

	await Promise.all(files.map(async file => {
		const bytes = new Uint8Array(await file.arrayBuffer());

		const b64 = btoa(
			Array.from(bytes, byte => String.fromCharCode(byte)).join("")
		);

		await rpc.addTorrent(b64);
	}));

    input.value = "";
    await refreshTable();
};

// open details for selected row
el.torrents.addEventListener("click", async event => {
    if (!js()) return;

    if (event.target.closest("a, input, select")) 
		return;

    const row = event.target.closest("tr");
    if (!row || !el.torrents.contains(row)) 
		return;

	const id = +row.dataset.id;
	if (!id) 
		return;

	const ctrl = event.ctrlKey || event.metaKey
	const shift = event.shiftKey

	if (shift) {
		// range selecting
		event.preventDefault();
		const arr = util.sel.getAllIDs();

		const a = arr.indexOf(selected_torrent);
		const b = arr.indexOf(id);
		const r = arr.slice(
			Math.min(a, b), 
			Math.max(a, b) + 1
		);

		ctrl ? util.sel.deselectIDs(r) : util.sel.selectIDs(r);
		
	} else if (ctrl) {
		// single selecting
		event.preventDefault();
		util.sel.toggleID(id)
	}

	selected_torrent = id;

	await refreshTable({ fetchTorrents: false });
});

// prevent text from being selected when a range is selected
el.torrents.addEventListener("mousedown", event => {
    if (event.shiftKey)
		event.preventDefault();
});

// rcm (right-click-menu) for torrent table
el.torrents.addEventListener("contextmenu", async event => {
    const row = event.target.closest("tr");

    if (!row || !el.torrents.contains(row)) 
		return;

	const id = +row.dataset.id;
	if (!id) 
		return;

	const torrent = torrents.find(t => t.id == id);
	if (!torrent) 
		return;

	const running = torrent.status > 0

    event.preventDefault();

    selected_torrent = id;
	refreshTable({ fetchTorrents: false });
	
	// cleaning rcm
	el.torrent_rcm.replaceChildren();

	if (util.sel.isEnabled()) {
		if (util.sel.isSomeStopped()) {
			const start = document.createElement("div");
			start.dataset.action = "start";
			start.textContent = "▶️ Start selected";
			el.torrent_rcm.append(start);
		}

		if (util.sel.isSomeRunning()) {
			const pause = document.createElement("div");
			pause.dataset.action = "pause";
			pause.textContent = "⏸️ Pause selected";
			el.torrent_rcm.append(pause);

			const reannounce = document.createElement("div");
			reannounce.dataset.action = "reannounce";
			reannounce.textContent = "🔄 Reannounce selected";
			el.torrent_rcm.append(reannounce);
		}
	}
	else {
		const setStatus = document.createElement("div");
		setStatus.dataset.action = running ? "pause" : "start";
		setStatus.textContent = running ? "⏸️ Pause" : "▶️ Start";
		el.torrent_rcm.append(setStatus);

		if (running) {
			const reannounce = document.createElement("div");
			reannounce.dataset.action = "reannounce";
			reannounce.textContent = "🔄 Reannounce";
			el.torrent_rcm.append(reannounce);
		}
	}

	// separator
	el.torrent_rcm.append(document.createElement("hr"));
	
	const toggle = document.createElement("div");
	toggle.dataset.action = "toggle";
	toggle.textContent = util.sel.isSelected(id)
		? "❎ Unselect" 
		: "✅ Select";
	el.torrent_rcm.append(toggle);

	const toggle_all = document.createElement("div");
	toggle_all.dataset.action = "toggle_all";
	toggle_all.textContent = util.sel.allChecked() 
		? "❎ Unselect all" 
		: "✅ Select all";
	el.torrent_rcm.append(toggle_all);
	
	// separator
	el.torrent_rcm.append(document.createElement("hr"));

	// delete .torrent
	const magnet = document.createElement("div");
	magnet.dataset.action = "magnet";
	magnet.textContent = util.sel.isEnabled() 
		? "🧲 Copy magnet links" 
		: "🧲 Copy magnet link";
	el.torrent_rcm.append(magnet);

	// separator
	el.torrent_rcm.append(document.createElement("hr"));

	// delete .torrent
	const delete_ = document.createElement("div");
	delete_.dataset.action = "delete";
	delete_.textContent = util.sel.isEnabled() 
		? "🗑️ Delete selected" 
		: "🗑️ Delete";
	el.torrent_rcm.append(delete_);

	// delete .torrent and downloaded files
	const deletefiles = document.createElement("div");
	deletefiles.dataset.action = "delete_files";
	deletefiles.textContent = util.sel.isEnabled() 
		? "❌ Delete selected with files" 
		: "❌ Delete with files";
	el.torrent_rcm.append(deletefiles);

    // move the menu directly into the body
    document.body.appendChild(el.torrent_rcm);

    el.torrent_rcm.hidden = false;
    el.torrent_rcm.style.position = "fixed";
    el.torrent_rcm.style.left = `${event.clientX}px`;
    el.torrent_rcm.style.top = `${event.clientY}px`;

    // adjust the position if the menu extends beyond the window's boundaries
    const rect = el.torrent_rcm.getBoundingClientRect();

    if (rect.right > window.innerWidth - 5)
        el.torrent_rcm.style.left = `${Math.max(5, window.innerWidth - rect.width - 5)}px`;

    if (rect.bottom > window.innerHeight - 5)
        el.torrent_rcm.style.top = `${Math.max(5, window.innerHeight - rect.height - 5)}px`;
});

// performing the selected rcm action
el.torrent_rcm.addEventListener("click", async event => {
    const item = event.target.closest("[data-action]");
    if (!item || !el.torrent_rcm.contains(item)) 
		return;

	const torrentActions = {
		start: async ids => rpc.torrentStart(ids),
		pause: async ids => rpc.torrentStop(ids),
		reannounce: async ids => rpc.torrentReannounce(ids),
		delete: async ids => torrentRemove(ids, false),
		delete_files: async ids => torrentRemove(ids, true),
		toggle: ids => util.sel.toggleID(selected_torrent),
		toggle_all: ids => util.sel.toggleAll(),
		magnet: ids => util.copy.magnets( util.sel.idsToObj(ids) )
	};

    const action = torrentActions[item.dataset.action];
    if (!action || !selected_torrent || !js()) 
		return;

    el.torrent_rcm.hidden = true;

    action(selected_torrents.length ? selected_torrents : [selected_torrent]);

	let fetchTorrents = false
	if (['start', 'pause', 'reannounce'].includes(item.dataset.action)) {
		util.sel.deselectAll();
		fetchTorrents = true
	}

    await refreshTable({ fetchTorrents: fetchTorrents });
});

// close the rcm by clicking outside
document.addEventListener("click", event => {
    if (!el.torrent_rcm.contains(event.target))
        el.torrent_rcm.hidden = true;
});

// hotkeys
document.addEventListener("keydown", event => {
	const ids = selected_torrents.length ? selected_torrents : [selected_torrent]

	const up = event.key === "ArrowUp" || event.key === "ArrowLeft"
	const down = event.key === "ArrowRight" || event.key === "ArrowDown"

	const esc = event.key === "Escape"
	const space = event.code === "Space"
	const shift = event.shiftKey
	const ctrl = event.ctrlKey || event.metaKey
	const ctrl_a = ctrl && event.code === "KeyA"
	const ctrl_c = ctrl && event.code === "KeyC"

	const start = event.code === "KeyS" || event.code === "F3"
	const pause = event.code === "KeyP" || event.code === "F4"
	const reannounce = event.code === "KeyR"

	const delete_ = event.code === "Delete"
	const delete_files = (shift || ctrl) && delete_

	// actions
	const action = start || pause || reannounce || delete_ || delete_files
	if (action && ids.length) {
		event.preventDefault();
		if (start)
			rpc.torrentStart(ids)
		else if (pause)
			rpc.torrentStop(ids)
		else if (reannounce)
			rpc.torrentReannounce(ids)
		else if (delete_files)
			torrentRemove(ids, true);
		else if (delete_)
			torrentRemove(ids, false)
		refreshTable({ fetchTorrents: true });
		return;
	}

	// select all torrents
    if (ctrl_a) {
        event.preventDefault();
        util.sel.selectAll()
		refreshTable({ fetchTorrents: false });
		return;
    }

	// copy magnet link
    if (ctrl_c) {
        event.preventDefault();
		if (ids.length)
        	util.copy.magnets( util.sel.idsToObj(ids) );
		return;
    }

	// closing stuff
    if (esc) {
		if (!el.torrent_rcm.hidden) {
			// close rcm
			el.torrent_rcm.hidden = true;
		}
		else if (selected_torrents.length) {
			// deselecting torrents
			selected_torrents = []
			refreshTable({ fetchTorrents: false }); 
		}
		else if (selected_torrent) {
			// close details
			closeTorrentDetails();
		}
		return;
	}

	// select current torrent
    if (selected_torrent && space) {
        event.preventDefault();
        util.sel.toggleID(selected_torrent)
		refreshTable({ fetchTorrents: false });
		return;
    }

	// moving selector
    if (selected_torrent && (up || down)){
		event.preventDefault();

		let idx = util.sel.objIdx(selected_torrent);
		if (up)
			idx -= 1
		if (down) 
			idx += 1

		if (!torrents[idx])
			return;

		if (shift) 
			util.sel.selectID(selected_torrent)

		selected_torrent = torrents[idx].id

		if (ctrl)
			util.sel.toggleID(selected_torrent)
		else if (shift)
			util.sel.selectID(selected_torrent)

		refreshTable({ fetchTorrents: false }); 

		return;
	}
});

async function refreshSessionStats() {
  	if (!js()) return;

	const r = await rpc.sessionStats();
	
	if (!r?.arguments?.["current-stats"])
		return (el.fs_session_stats.style.display = "none")

	const list = util.list.session(r.arguments["current-stats"])

	el.session_stats_list.replaceChildren(list)
	el.fs_session_stats.style.display = "block";
}

async function refreshDhtStats() {
  	if (!js()) return;

	const r = await rpc.dhtStats();
	
	if (!r?.arguments)
		return (el.fs_dht_stats.style.display = "none")

	const list = util.list.dht(r.arguments)

	el.dht_stats_list.replaceChildren(list)
	el.fs_dht_stats.style.display = "block";
}

// refresh table with torrents
async function refreshTable({
    closeDetails = false, fetchTorrents = true
} = {}) {
	if (!window.rpc)
		return vis_exh('failed to load rpc.js', "")

	if (!window.util)
		return vis_exh('failed to load utils.js', "")

	if (fetchTorrents || !torrents.length) {
		const r = await rpc.torrentGet();

		if (r?.result !== "success")
			return vis_exh('failed response', r)

		torrents = r.arguments.torrents;
	}

	if (!torrents.length) {
		el.torrents.replaceChildren();
		vis_exh();
		return;
	}

	if (closeDetails)
		selected_torrent = 0

	tr_table = util.table.torrents(torrents)

	const fs = document.createElement("fieldset");

	const legend = document.createElement("legend");
	let legend_txt =  `Torrents: ${torrents.length}`
	if (selected_torrents.length)
		legend_txt += `, Selected: ${selected_torrents.length}`
	legend.textContent = legend_txt
	fs.append(legend, tr_table.table);

	el.torrents.replaceChildren(fs);

	document.title = 
		`↓${util.fmt.bytes(tr_table.allDw)} ↑${util.fmt.bytes(tr_table.allUp)}`;

	selected_torrent
		? openTorrentDetails(selected_torrent)
		: el.details.replaceChildren();

	vis_exh();
	util.sel.clearIDs();
}

function openTorrentDetails(id) {
  	if (!js()) return;

	const torrent = torrents.find(t => t.id == id);
	if (!torrent) 
		return;

	selected_torrent = torrent.id

	const fs = document.createElement("fieldset");

	const content = document.createElement("div");
	content.style.display = "flex";
	content.style.justifyContent = "space-between";
	content.style.width = "100%";

	const lable = document.createElement("span");
	lable.textContent = `#${torrent.id}: ${torrent.name}`;

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
		util.list.torrent(torrent),
		util.table.peers(torrent.peers),
		util.table.trackers(torrent.trackerStats),
		util.table.files(torrent.files)
	);

	el.details.replaceChildren(fs);
};

function closeTorrentDetails() {
	refreshTable({ closeDetails: true, fetchTorrents: false });
};