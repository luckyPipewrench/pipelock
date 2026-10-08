// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Go's js/wasm os package expects a synchronous Node-style fs interface. The
// stock browser wasm_exec.js stub intentionally returns ENOSYS for file calls.
// This small private filesystem lets the verifier inspect a bounded receipt
// archive without giving the browser or verifier access to host files.
(() => {
	// Leave a real host filesystem alone. Go's stock browser shim uses -1 for
	// every unused open flag; that is the marker that a memory filesystem is
	// needed. A Node host has its own usable fs implementation.
	if (globalThis.fs?.constants?.O_DIRECTORY !== -1) return;

	const dirs = new Map();
	const files = new Map();
	const handles = new Map();
	let nextFD = 3;
	let nextInode = 10;
	const now = 0;

	const normalize = (value) => {
		const parts = [];
		for (const part of String(value).replaceAll("\\", "/").split("/")) {
			if (!part || part === ".") continue;
			if (part === "..") parts.pop();
			else parts.push(part);
		}
		return `/${parts.join("/")}`;
	};
	const parent = (value) => value.slice(0, value.lastIndexOf("/")) || "/";
	const base = (value) => value.slice(value.lastIndexOf("/") + 1);
	const callback = (cb, err, value) => cb(err || null, value);
	const error = (code, message = code) => Object.assign(new Error(message), { code });
	const ensureParents = (value) => {
		const pieces = normalize(value).split("/").filter(Boolean);
		let path = "";
		for (const piece of pieces) {
			path += `/${piece}`;
			if (!dirs.has(path) && !files.has(path)) dirs.set(path, nextInode++);
		}
	};
	const node = (value) => {
		const path = normalize(value);
		if (dirs.has(path)) return { path, directory: true, inode: dirs.get(path) };
		const data = files.get(path);
		if (data) return { path, directory: false, inode: data.inode, data };
		throw error("ENOENT", `no such file or directory: ${path}`);
	};
	const stat = (item) => ({
		dev: 1,
		ino: item.inode,
		mode: item.directory ? 0o40750 : 0o100600,
		nlink: 1,
		uid: 0,
		gid: 0,
		rdev: 0,
		size: item.directory ? 0 : item.data.bytes.length,
		blksize: 4096,
		blocks: Math.ceil((item.directory ? 0 : item.data.bytes.length) / 512),
		atimeMs: now,
		mtimeMs: item.directory ? now : item.data.mtime,
		ctimeMs: now,
		isDirectory: () => item.directory,
		isSymbolicLink: () => false,
	});
	const readNames = (path) => {
		if (!dirs.has(path)) throw error("ENOTDIR");
		const prefix = path === "/" ? "/" : `${path}/`;
		const names = new Set();
		for (const child of dirs.keys()) {
			if (!child.startsWith(prefix) || child === path) continue;
			const rest = child.slice(prefix.length);
			if (rest && !rest.includes("/")) names.add(rest);
		}
		for (const child of files.keys()) {
			if (!child.startsWith(prefix)) continue;
			const rest = child.slice(prefix.length);
			if (rest && !rest.includes("/")) names.add(rest);
		}
		return [...names].sort();
	};
	let output = "";
	const writeOutput = (fd, buffer, offset, length, cb) => {
		if (fd !== 1 && fd !== 2) return callback(cb, error("EBADF"));
		output += new TextDecoder().decode(buffer.subarray(offset, offset + length));
		const lastNewline = output.lastIndexOf("\n");
		if (lastNewline >= 0) {
			const line = output.slice(0, lastNewline);
			output = output.slice(lastNewline + 1);
			(fd === 2 ? console.error : console.log)(line);
		}
		if (cb) callback(cb, null, length, buffer);
		return length;
	};
	const fs = {
		constants: {
			O_WRONLY: 1,
			O_RDWR: 2,
			O_CREAT: 64,
			O_EXCL: 128,
			O_TRUNC: 512,
			O_APPEND: 1024,
			O_DIRECTORY: 65536,
		},
		writeSync(fd, buffer) {
			const length = writeOutput(fd, buffer, 0, buffer.length);
			return length;
		},
		open(path, flags, _mode, cb) {
			path = normalize(path);
			const directory = (flags & fs.constants.O_DIRECTORY) !== 0;
			if (directory && !dirs.has(path)) return callback(cb, error("ENOTDIR"));
			if (dirs.has(path) && (flags & fs.constants.O_CREAT) !== 0) {
				// A create must never replace a directory with a file.
				return callback(cb, error((flags & fs.constants.O_EXCL) !== 0 ? "EEXIST" : "EISDIR"));
			}
			if (dirs.has(path) && (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR)) !== 0) {
				return callback(cb, error("EISDIR"));
			}
			let data = files.get(path);
			// O_EXCL fails only when the file existed before this open created it.
			if (data && (flags & fs.constants.O_EXCL) !== 0 && (flags & fs.constants.O_CREAT) !== 0) {
				return callback(cb, error("EEXIST"));
			}
			if (!data && (flags & fs.constants.O_CREAT) !== 0) {
				ensureParents(parent(path));
				data = { bytes: new Uint8Array(), inode: nextInode++, mtime: now };
				files.set(path, data);
			} else if (!data && !dirs.has(path)) {
				return callback(cb, error("ENOENT"));
			}
			if (data && (flags & fs.constants.O_TRUNC) !== 0) data.bytes = new Uint8Array();
			const fd = nextFD++;
			handles.set(fd, { path, position: (flags & fs.constants.O_APPEND) !== 0 && data ? data.bytes.length : 0 });
			callback(cb, null, fd);
		},
		close(fd, cb) {
			if (!handles.delete(fd)) return callback(cb, error("EBADF"));
			callback(cb, null);
		},
		fstat(fd, cb) {
			const h = handles.get(fd);
			if (!h) return callback(cb, error("EBADF"));
			try { callback(cb, null, stat(node(h.path))); } catch (err) { callback(cb, err); }
		},
		stat(path, cb) {
			try { callback(cb, null, stat(node(path))); } catch (err) { callback(cb, err); }
		},
		lstat(path, cb) {
			try { callback(cb, null, stat(node(path))); } catch (err) { callback(cb, err); }
		},
		readdir(path, cb) {
			try { callback(cb, null, readNames(normalize(path))); } catch (err) { callback(cb, err); }
		},
		mkdir(path, _mode, cb) {
			path = normalize(path);
			if (dirs.has(path) || files.has(path)) return callback(cb, error("EEXIST"));
			if (!dirs.has(parent(path))) return callback(cb, error("ENOENT"));
			dirs.set(path, nextInode++);
			callback(cb, null);
		},
		read(fd, buffer, offset, length, position, cb) {
			const h = handles.get(fd);
			const data = h && files.get(h.path);
			if (!h || !data) return callback(cb, error("EBADF"));
			const start = position === null ? h.position : Number(position);
			const count = Math.max(0, Math.min(length, data.bytes.length - start));
			buffer.set(data.bytes.subarray(start, start + count), offset);
			if (position === null) h.position += count;
			cb(null, count, buffer);
		},
		// One write for every descriptor: Go's runtime writes stdout and stderr
		// through the callback form, and a second definition later in this
		// literal would otherwise shadow the first and answer EBADF.
		write(fd, buffer, offset, length, position, cb) {
			if (fd === 1 || fd === 2) {
				if (position !== null) return callback(cb, error("EINVAL"));
				writeOutput(fd, buffer, offset, length, cb);
				return;
			}
			const h = handles.get(fd);
			const data = h && files.get(h.path);
			if (!h || !data) return callback(cb, error("EBADF"));
			const start = position === null ? h.position : Number(position);
			const end = start + length;
			if (end > data.bytes.length) {
				const grown = new Uint8Array(end);
				grown.set(data.bytes);
				data.bytes = grown;
			}
			data.bytes.set(buffer.subarray(offset, offset + length), start);
			if (position === null) h.position = end;
			data.mtime = now;
			callback(cb, null, length, buffer);
		},
		fsync(_fd, cb) { callback(cb, null); },
		ftruncate(fd, length, cb) {
			const h = handles.get(fd);
			const data = h && files.get(h.path);
			if (!h || !data) return callback(cb, error("EBADF"));
			const resized = new Uint8Array(length);
			resized.set(data.bytes.subarray(0, length));
			data.bytes = resized;
			callback(cb, null);
		},
		truncate(path, length, cb) {
			const data = files.get(normalize(path));
			if (!data) return callback(cb, error("ENOENT"));
			const resized = new Uint8Array(length);
			resized.set(data.bytes.subarray(0, length));
			data.bytes = resized;
			callback(cb, null);
		},
		unlink(path, cb) {
			path = normalize(path);
			if (!files.delete(path)) return callback(cb, error(dirs.has(path) ? "EISDIR" : "ENOENT"));
			callback(cb, null);
		},
		rmdir(path, cb) {
			path = normalize(path);
			if (!dirs.has(path)) return callback(cb, error("ENOENT"));
			if (readNames(path).length) return callback(cb, error("ENOTEMPTY"));
			dirs.delete(path);
			callback(cb, null);
		},
		rename(from, to, cb) {
			from = normalize(from);
			to = normalize(to);
			const data = files.get(from);
			if (!data || !dirs.has(parent(to))) return callback(cb, error("ENOENT"));
			files.delete(from);
			files.set(to, data);
			callback(cb, null);
		},
	};
	globalThis.fs = fs;
	globalThis.path = { resolve: (...parts) => normalize(parts.join("/")) };
	globalThis.pipelockMountReceiptGroup = (root, entries) => {
		root = normalize(root);
		ensureParents(root);
		for (const [name, value] of Object.entries(entries)) {
			const target = normalize(`${root}/${name}`);
			if (!target.startsWith(`${root}/`)) throw new Error("receipt archive path escaped its root");
			if (value === null) {
				ensureParents(target);
				continue;
			}
			ensureParents(parent(target));
			const bytes = value instanceof Uint8Array ? value.slice() : new Uint8Array(value);
			files.set(target, { bytes, inode: nextInode++, mtime: now });
		}
		return root;
	};
	globalThis.pipelockUnmountReceiptGroup = (root) => {
		root = normalize(root);
		for (const path of [...files.keys()]) if (path.startsWith(`${root}/`)) files.delete(path);
		for (const path of [...dirs.keys()].sort((a, b) => b.length - a.length)) {
			if (path === root || path.startsWith(`${root}/`)) dirs.delete(path);
		}
	};
	dirs.set("/", nextInode++);
	ensureParents("/tmp");
})();
