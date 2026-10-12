class TorrentClient {
    getEndpoint() {
        return `../rpc`;
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

    async addTorrentByMagnet(magnet)
    {
        // TODO: check link
        const magnetRegex = /^magnet:\?xt=urn:btih:[a-f0-9]{40}(&.+)?$/i;
        if(!magnetRegex.test(magnet)) return false;
        const res = await fetch(this.getEndpoint(), {
            method: "POST",
            body: JSON.stringify({ 'method': 'torrent-add', 'arguments': { 'filename': magnet } }),
                                headers: { 'Content-Type': 'application/json' }
        });
        return res.json();

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
                'arguments': { "fields": ["id", "name", "status", "rateDownload", "rateUpload", "totalSize", "percentDone", "files", "peers", "trackers", "trackerStats","hashString"] }
            }),
            headers: { 'Content-Type': 'application/json' }
        });
        return res.json();
    }
   async stopTorrent(ids = []) {
    const res = await fetch(this.getEndpoint(), {
        method: "POST",
        body: JSON.stringify({
            'method': 'torrent-stop', 
            'arguments': ids.length ? { ids } : {}, 
            'tag': 666
        }),
        headers: { 'Content-Type': 'application/json' }
    });
    return res.json();
}

async startTorrent(ids = []) {
    const res = await fetch(this.getEndpoint(), {
        method: "POST",
        body: JSON.stringify({
            'method': 'torrent-start',
            'arguments': ids.length ? { ids } : {}, 
            'tag': 666
        }),
        headers: { 'Content-Type': 'application/json' }
    });
    return res.json();
} 
}