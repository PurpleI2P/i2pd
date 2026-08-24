class TorrentClient {
    constructor(host = '127.0.0.1', port = 9191, path = 'mytorrents') {
        this.host = host;
        this.port = port;
        this.path = path;
    }

    setConnection(host, port, path) {
        this.host = host;
        this.port = port;
        this.path = path;
    }

    getEndpoint() {
        return `http://${this.host}:${this.port}${this.path}`;
    }

    getStatusString(status) {
        switch (status) {
            case 4: return 'DOWNLOADING';
            case 6: return 'SEEDING';
            case 0: return 'STOPPED';
            case 2: return 'CHECKING';
            default: return 'QUEUED';
        }
    }

    formatBytes(bytesPerSec) {
        if (!bytesPerSec) return '0 B/s';
        if (bytesPerSec > 1024 * 1024) {
            return (bytesPerSec / (1024 * 1024)).toFixed(2) + ' MB/s';
        }
        return (bytesPerSec / 1024).toFixed(2) + ' KB/s';
    }

    async addTorrent(b64metainfo) {
        const res = await fetch(this.getEndpoint(), {
            method: "POST",
            body: JSON.stringify({ 'method': 'torrent-add', 'arguments': { 'metainfo': b64metainfo } }),
                                headers: { 'Content-Type': 'application/json' }
        });
        return res.json();
    }

    async removeTorrent(id) {
        const res = await fetch(this.getEndpoint(), {
            method: "POST",
            body: JSON.stringify({ 'method': 'torrent-remove', 'arguments': { 'ids': [id], 'delete-local-data': true } }),
                                headers: { 'Content-Type': 'application/json' }
        });
        return res.json();
    }

    async getTorrents() {
        const res = await fetch(this.getEndpoint(), {
            method: "POST",
            body: JSON.stringify({
                'method': 'torrent-get',
                'arguments': { "fields": ["id", "name", "status", "rateDownload", "rateUpload", "totalSize", "percentDone"] }
            }),
            headers: { 'Content-Type': 'application/json' }
        });
        return res.json();
    }
}

//window.tjs = new TorrentClient();
