class TorrentClient {
    endpoint = "../rpc"

	torrent_fields = [
        "id",
        "name",
        "status",
        "pieceCount",
        "pieceSize",
        "rateDownload",
        "rateUpload",
        "totalSize",
        "haveValid",
        "percentDone",
        "files",
        "peers",
        "trackers",
        "trackerStats",
        "magnetLink",
        "hashString",
		"metadataPercentComplete"
    ]

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
	}

	async addTorrentByMagnet(magnet) {
		return this.request("torrent-add", { filename: magnet });
	}

	async addTorrent(b64metainfo) {
		return this.request("torrent-add", { metainfo: b64metainfo });
	}

	async removeTorrent(id, deletefiles = false) {
		if (Array.isArray(id) && id.length === 0) 
			return;

		return this.request("torrent-remove", {
			ids: Array.isArray(id) ? id : [id],
			"delete-local-data": deletefiles
		});
	}

	async torrentGet() {
		return this.request("torrent-get", {
			fields: this.torrent_fields
		});
	}

	async sessionStats() {
		return this.request("session-stats");
	}

	async dhtStats() {
		return this.request("dht-stats");
	}

	async torrentStop(ids = []) {
		return this.request("torrent-stop", ids.length ? { ids } : {});
	}

	async torrentStart(ids = []) {
		return this.request("torrent-start", ids.length ? { ids } : {});
	}

	async torrentReannounce(ids = []) {
		return this.request("torrent-reannounce", ids.length ? { ids } : {});
	}
}