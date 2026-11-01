// update delays
const upd_delay = {
	session_stats: 10 * 1000, // 10 sec
	dht_stats: 30 * 1000, // 30 sec
	torrents: 5 * 1000 // 5 sec
}

// global vars
let gl = {
	// torrent objects for refreshTable()
	torrents: [],

	// torrent id from refreshTable() for openTorrentDetails()
	selector: 0,

	// selection of torrent id's from refreshTable() for actions
	selected: [],

	// table sorting
	sort: {
		torrents: { enabled: false, row: 0, reverse: false },
		peers: 	  { enabled: false, row: 0, reverse: false },
		trackers: { enabled: false, row: 0, reverse: false },
		files: 	  { enabled: false, row: 0, reverse: false }
	}
};

// html elements
const el = {
    rcm: document.getElementById("rcm"),

    error: document.getElementById("error"),
    error_message: document.getElementById("error-message"),
    error_details: document.getElementById("error-details"),

    file_dialog: document.getElementById("file-dialog"),

    dht_stats_fs: document.getElementById("dht-stats-fs"),
    dht_stats_list: document.getElementById("dht-stats-list"),

    session_stats_fs: document.getElementById("session-stats-fs"),
    session_stats_list: document.getElementById("session-stats-list"),

    torrents: document.getElementById("torrents"),
    details: document.getElementById("details")
};

function now_ts() { return Math.floor(Date.now() / 1000) };
let exh_ts = 0;

// display errors
function vis_exh(message = "", details = "") {
	const is_blank = !message && !details;

	if (is_blank && now_ts() - exh_ts < 30)
		return;

	exh_ts = now_ts()

	el.error.style.display = is_blank ? "none" : "block";
	el.error_message.textContent = message;
	el.error_details.textContent = details;
	if (!is_blank) {
		console.log(message)
		console.log(details)
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
	return Boolean(window.util)
}

// add local torrent files
el.file_dialog.onchange = async (e) => {
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

		await util.rpc.torrent.addFile(b64);
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
		const arr = util.tr.all.get_ids();

		const a = arr.indexOf(gl.selector);
		const b = arr.indexOf(id);
		const r = arr.slice(
			Math.min(a, b), 
			Math.max(a, b) + 1
		);

		ctrl ? util.tr.deselect_ids(r) : util.tr.select_ids(r);
		
	} else if (ctrl) {
		// single selecting
		event.preventDefault();
		if (!util.tr.selected() && gl.selector != id) 
			util.tr.select_id(gl.selector)
		util.tr.toggle_id(id)
	}

	gl.selector = id;

	await refreshTable({ fetchTorrents: false });
});

// prevent text from being selected when a range is selected
el.torrents.addEventListener("mousedown", event => {
    if (event.shiftKey)
		event.preventDefault();
});

// rcm (right-click-menu) for torrent table
el.torrents.addEventListener("contextmenu", async event => {
    if (!js()) return;

    const row = event.target.closest("tr");

    if (!row || !el.torrents.contains(row)) 
		return;

	const id = +row.dataset.id;
	if (!id) 
		return;

	const torrent = util.tr.all.find_by_id(id);
	if (!torrent) 
		return;

	const running = torrent.status > 0

    event.preventDefault();

    gl.selector = id;
	refreshTable({ fetchTorrents: false });
	
	// cleaning rcm
	el.rcm.replaceChildren();

	if (util.tr.id_selected(gl.selector)) {
		if (util.tr.sel.some_stopped()) {
			const start = document.createElement("div");
			start.dataset.action = "start";
			start.textContent = "▶️ Start selected";
			el.rcm.append(start);
		}

		if (util.tr.sel.some_running()) {
			const pause = document.createElement("div");
			pause.dataset.action = "pause";
			pause.textContent = "⏸️ Pause selected";
			el.rcm.append(pause);

			const reannounce = document.createElement("div");
			reannounce.dataset.action = "reannounce";
			reannounce.textContent = "🔄 Reannounce selected";
			el.rcm.append(reannounce);
		}
	}
	else {
		const setStatus = document.createElement("div");
		setStatus.dataset.action = running ? "pause" : "start";
		setStatus.textContent = running ? "⏸️ Pause" : "▶️ Start";
		el.rcm.append(setStatus);

		if (running) {
			const reannounce = document.createElement("div");
			reannounce.dataset.action = "reannounce";
			reannounce.textContent = "🔄 Reannounce";
			el.rcm.append(reannounce);
		}
	}

	// separator
	el.rcm.append(document.createElement("hr"));
	
	const toggle = document.createElement("div");
	toggle.dataset.action = "toggle";
	toggle.textContent = util.tr.id_selected(id)
		? "❎ Unselect" 
		: "✅ Select";
	el.rcm.append(toggle);

	const toggle_all = document.createElement("div");
	toggle_all.dataset.action = "toggle_all";
	toggle_all.textContent = util.tr.all_selected() 
		? "❎ Unselect all" 
		: "✅ Select all";
	el.rcm.append(toggle_all);
	
	// separator
	el.rcm.append(document.createElement("hr"));

	// delete .torrent
	const magnet = document.createElement("div");
	magnet.dataset.action = "magnet";
	magnet.textContent = util.tr.id_selected(gl.selector)
		? "🧲 Copy magnet links" 
		: "🧲 Copy magnet link";
	el.rcm.append(magnet);

	// separator
	el.rcm.append(document.createElement("hr"));

	// delete .torrent
	const delete_ = document.createElement("div");
	delete_.dataset.action = "delete";
	delete_.textContent = util.tr.id_selected(gl.selector)
		? "🗑️ Delete selected" 
		: "🗑️ Delete";
	el.rcm.append(delete_);

	// delete .torrent and downloaded files
	const deletefiles = document.createElement("div");
	deletefiles.dataset.action = "delete_files";
	deletefiles.textContent = util.tr.id_selected(gl.selector)
		? "❌ Delete selected with files" 
		: "❌ Delete with files";
	el.rcm.append(deletefiles);

    // move the menu directly into the body
    document.body.appendChild(el.rcm);

    el.rcm.hidden = false;
    el.rcm.style.position = "fixed";
    el.rcm.style.left = `${event.clientX}px`;
    el.rcm.style.top = `${event.clientY}px`;

    // adjust the position if the menu extends beyond the window's boundaries
    const rect = el.rcm.getBoundingClientRect();

    if (rect.right > window.innerWidth - 5)
        el.rcm.style.left = `${Math.max(5, window.innerWidth - rect.width - 5)}px`;

    if (rect.bottom > window.innerHeight - 5)
        el.rcm.style.top = `${Math.max(5, window.innerHeight - rect.height - 5)}px`;
});

// performing the selected rcm action
el.rcm.addEventListener("click", async event => {
    if (!js()) return;

    const item = event.target.closest("[data-action]");
    if (!item || !el.rcm.contains(item)) 
		return;

	const torrentActions = {
		start: async ids => util.rpc.torrent.start(ids),
		pause: async ids => util.rpc.torrent.stop(ids),
		reannounce: async ids => util.rpc.torrent.reannounce(ids),
		delete: async ids => util.dialog.torrentRemove(ids, false),
		delete_files: async ids => util.dialog.torrentRemove(ids, true),
		toggle: ids => util.tr.toggle_id(gl.selector),
		toggle_all: ids => util.tr.toggle_all(),
		magnet: ids => util.copy.magnets( util.tr.all.get(ids) )
	};

    const action = torrentActions[item.dataset.action];
    if (!action || !gl.selector) 
		return;

    el.rcm.hidden = true;

	const is_selected = util.tr.id_selected(gl.selector)

    action(is_selected ? gl.selected : [gl.selector]);

	let fetchTorrents = false;
	switch (item.dataset.action) {
		case 'start':
		case 'pause':
		case 'reannounce':
			fetchTorrents = true;
		case 'magnet':
			if (is_selected)
				util.tr.deselect_all();
			break;
	}

    await refreshTable({ fetchTorrents: fetchTorrents });
});

// close the rcm by clicking outside
document.addEventListener("click", event => {
    if (!el.rcm.contains(event.target))
        el.rcm.hidden = true;
});

// hotkeys
document.addEventListener("keydown", event => {
    if (!js()) return;

	const ids = util.tr.selected() ? gl.selected : [gl.selector]

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
			util.rpc.torrent.start(ids)
		else if (pause)
			util.rpc.torrent.stop(ids)
		else if (reannounce)
			util.rpc.torrent.reannounce(ids)
		else if (delete_files)
			util.dialog.torrentRemove(ids, true);
		else if (delete_)
			util.dialog.torrentRemove(ids, false)
		refreshTable({ fetchTorrents: true });
		return;
	}

	// select all torrents
    if (ctrl_a) {
        event.preventDefault();
        util.tr.select_all()
		refreshTable({ fetchTorrents: false });
		return;
    }

	// copy magnet link
    if (ctrl_c && util.tr.selected()) {
        event.preventDefault();
        util.copy.magnets( util.tr.sel.get() );
		util.tr.deselect_all()
		refreshTable({ fetchTorrents: false });
		return;
    }

	// closing stuff
    if (esc) {
		if (!el.rcm.hidden) {
			// close rcm
			el.rcm.hidden = true;
		}
		else if (util.tr.selected()) {
			// deselecting torrents
			util.tr.deselect_all();
			refreshTable({ fetchTorrents: false }); 
		}
		else if (gl.selector) {
			// close details
			closeTorrentDetails();
		}
		return;
	}

	// select current torrent
    if (gl.selector && space) {
        event.preventDefault();
        util.tr.toggle_id(gl.selector)
		refreshTable({ fetchTorrents: false });
		return;
    }

	// moving selector
    if (gl.selector && (up || down)){
		event.preventDefault();

		let idx = util.tr.all.idx(gl.selector);
		if (up)
			idx -= 1
		if (down) 
			idx += 1

		if (!gl.torrents[idx])
			return;

		if (shift) 
			util.tr.select_id(gl.selector)

		gl.selector = gl.torrents[idx].id

		if (ctrl)
			util.tr.toggle_id(gl.selector)
		else if (shift)
			util.tr.select_id(gl.selector)

		refreshTable({ fetchTorrents: false }); 

		return;
	}
});

async function refreshSessionStats() {
  	if (!js()) return;

	const r = await util.rpc.stats.session();
	
	if (!r?.arguments?.["current-stats"])
		return (el.session_stats_fs.style.display = "none")

	const list = util.list.session(r.arguments["current-stats"])

	el.session_stats_list.replaceChildren(list)
	el.session_stats_fs.style.display = "block";
}

async function refreshDhtStats() {
  	if (!js()) return;

	const r = await util.rpc.stats.dht();
	
	if (!r?.arguments)
		return (el.dht_stats_fs.style.display = "none")

	const list = util.list.dht(r.arguments)

	el.dht_stats_list.replaceChildren(list)
	el.dht_stats_fs.style.display = "block";
}

// refresh table with torrents
async function refreshTable({
    closeDetails = false, fetchTorrents = true
} = {}) {
	if (!window.util)
		return vis_exh('failed to load utils.js', "")

	if (fetchTorrents || !util.tr.all.count()) {
		const r = await util.rpc.torrent.get();

		if (r?.result !== "success")
			return vis_exh('failed response', r)

		gl.torrents = r.arguments.torrents;
	}

	if (!util.tr.all.count()) {
		el.torrents.replaceChildren();
		vis_exh();
		return;
	}

	util.tr.mrproper();

	if (closeDetails)
		gl.selector = 0

	el.torrents.replaceChildren(
		util.table.torrents(gl.torrents, gl.sort.torrents)
	);

	gl.selector
		? openTorrentDetails(gl.selector)
		: el.details.replaceChildren();

	vis_exh();
}

function openTorrentDetails(id) {
  	if (!js()) return;

	const torrent = util.tr.all.find_by_id(id);
	if (!torrent) 
		return;

	gl.selector = torrent.id

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
		util.table.peers(torrent.peers, gl.sort.peers),
		util.table.trackers(torrent.trackerStats, gl.sort.trackers),
		util.table.files(torrent.files, gl.sort.files)
	);

	el.details.replaceChildren(fs);
};

function closeTorrentDetails() {
	refreshTable({ closeDetails: true, fetchTorrents: false });
};

setInterval(
	async () => refreshSessionStats(), 
	upd_delay.session_stats
);
setInterval(
	async () => refreshDhtStats(), 
	upd_delay.dht_stats
);
setInterval(
	async () => refreshTable(), 
	upd_delay.torrents
);

refreshTable(); 
refreshDhtStats();
refreshSessionStats();