"use strict";

(() => {
  if (window.self !== window.top) {
    const blocked = document.getElementById("frameBlocked");
    const root = document.getElementById("appRoot");
    if (blocked) blocked.hidden = false;
    if (root) root.hidden = true;
    throw new Error("FRAME_EMBEDDING_BLOCKED");
  }

  const $ = (id) => document.getElementById(id);
  const el = {
    dropZone: $("dropZone"), dropTitle: $("dropTitle"),
    folderInput: $("folderInput"), zipInput: $("zipInput"), mdInput: $("mdRestoreInput"),
    secretMode: $("secretModeSelect"), boundary: $("boundarySelect"),
    selectFolder: $("btnSelectFolder"), selectZip: $("btnSelectZip"), selectMd: $("btnSelectMd"),
    selfTest: $("btnSelfTest"), clearMemory: $("btnClearMemory"), copyMd: $("btnCopyMd"),
    downloadMd: $("btnDownloadMd"), downloadZip: $("btnDownloadRestoredZip"),
    writeFolder: $("btnWriteToFolder"), cancel: $("btnCancel"), clearLog: $("btnClearLog"),
    reviewed: $("confirmReviewedCheck"), badge: $("statBadge"), meta: $("metaInfo"),
    empty: $("emptyState"), preview: $("previewBox"), status: $("statusBox"),
    logSection: $("logSection"), log: $("logBox")
  };

  const MAX_LOG_LINES = 200;
  const MAX_ENTRIES = 10000;
  const SCAN_TIMEOUT_MS = 20000;
  const MAX_MD_BYTES = 45 * 1024 * 1024;
  const MAX_ZIP_BYTES = 50 * 1024 * 1024;
  const PREVIEW_MAX_CHARS = 10000;
  let currentJob = null;
  let markdownBlob = null;
  let restoredZipBlob = null;
  let activeObjectUrl = null;
  let currentRootName = "project";
  let dragDepth = 0;

  function setStatus(message, isError = false) {
    el.status.textContent = message;
    el.status.classList.toggle("error", Boolean(isError));
  }

  function appendLog(message) {
    el.logSection.hidden = false;
    while (el.log.childNodes.length >= MAX_LOG_LINES) el.log.removeChild(el.log.firstChild);
    const line = document.createElement("div");
    line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    el.log.appendChild(line);
    el.log.scrollTop = el.log.scrollHeight;
  }

  function revokeObjectUrl() {
    if (activeObjectUrl) {
      URL.revokeObjectURL(activeObjectUrl);
      activeObjectUrl = null;
    }
  }

  function releaseOutputMemory() {
    revokeObjectUrl();
    markdownBlob = null;
    restoredZipBlob = null;
    currentRootName = "project";
    el.preview.textContent = "";
    el.preview.hidden = true;
    el.empty.hidden = false;
    el.reviewed.checked = false;
    el.reviewed.disabled = true;
    el.clearMemory.disabled = true;
    updateOutputButtons();
  }

  function updateStats(stats, mode = "変換") {
    if (!stats) {
      el.badge.textContent = "待機中";
      el.meta.textContent = "まだファイルが読み込まれていません。";
      return;
    }
    const kb = ((stats.totalBytes || 0) / 1024).toFixed(1);
    if (mode === "復元") {
      el.badge.textContent = `復元可能 ${stats.restoredFiles || 0} 件`;
      el.meta.textContent = `モード: ディレクトリ復元 ｜ ルート名: ${currentRootName} ｜ ファイル: ${(stats.restoredFiles || 0).toLocaleString()}件 ｜ サブディレクトリ: ${(stats.restoredDirs || 0).toLocaleString()}個 ｜ 合計: ${kb} KB`;
    } else {
      el.badge.textContent = `採用 ${stats.processedFiles || 0} 件`;
      el.meta.textContent = `走査: ${(stats.scannedEntries || 0).toLocaleString()}件 ｜ 採用: ${(stats.processedFiles || 0).toLocaleString()}件 ｜ 機密除外: ${(stats.secretFilesBlocked || 0) + (stats.contentSecretSkipped || 0)}件 ｜ マスク: ${stats.redactedSecretsCount || 0}箇所 ｜ 推定トークン: 約${(stats.estimatedTokens || 0).toLocaleString()} ｜ ${kb} KB`;
    }
  }

  function updateOutputButtons() {
    const confirmed = el.reviewed.checked && !currentJob;
    const hasMarkdown = Boolean(markdownBlob);
    const canRestore = Boolean(restoredZipBlob || markdownBlob);
    el.copyMd.disabled = !hasMarkdown || !confirmed;
    el.downloadMd.disabled = !hasMarkdown || !confirmed;
    el.downloadZip.disabled = !canRestore || !confirmed;
    el.writeFolder.disabled = !canRestore || !confirmed || typeof window.showDirectoryPicker !== "function";
  }

  function setBusy(message) {
    releaseOutputMemory();
    el.badge.textContent = "処理中";
    setStatus(message || "安全に解析・検証しています…");
    [el.selectFolder, el.selectZip, el.selectMd, el.selfTest].forEach((button) => { button.disabled = true; });
    el.cancel.disabled = false;
    el.dropZone.classList.add("disabled");
    el.dropTitle.textContent = "処理中です。完了までお待ちください。";
    updateOutputButtons();
  }

  function setIdle(keepOutput = false) {
    if (!keepOutput) {
      releaseOutputMemory();
      updateStats(null);
    } else {
      el.reviewed.disabled = false;
      el.clearMemory.disabled = false;
    }
    [el.selectFolder, el.selectZip, el.selectMd, el.selfTest].forEach((button) => { button.disabled = false; });
    el.cancel.disabled = true;
    el.dropZone.classList.remove("disabled");
    el.dropTitle.textContent = "ここにフォルダ・ZIP・Markdownをドロップ";
    updateOutputButtons();
  }

  function cancelActiveJob(reason = "JOB_CANCELLED") {
    if (!currentJob) return false;
    const job = currentJob;
    currentJob = null;
    job.abortController.abort();
    if (job.cancelWorker) job.cancelWorker(new Error(reason));
    return true;
  }

  function runWorker(payload, transferList = [], job = null) {
    return new Promise((resolve, reject) => {
      let settled = false;
      let worker;
      const finish = (callback, value) => {
        if (settled) return;
        settled = true;
        if (worker) {
          worker.onmessage = null;
          worker.onerror = null;
          worker.terminate();
          worker = null;
        }
        if (job) job.cancelWorker = null;
        callback(value);
      };
      try {
        worker = new Worker(new URL("./worker.js", document.baseURI));
      } catch (error) {
        reject(new Error(`Workerを起動できません。HTTP/HTTPS経由で開いてください。${error.message ? ` (${error.message})` : ""}`));
        return;
      }
      if (job) {
        if (job.abortController.signal.aborted) {
          finish(reject, new Error("JOB_CANCELLED"));
          return;
        }
        job.cancelWorker = (error) => finish(reject, error);
      }
      worker.onmessage = (event) => {
        const data = event.data || {};
        if (data.type === "progress") updateStats(data.stats);
        else if (data.type === "complete" || data.type === "restore_complete") finish(resolve, data);
        else if (data.type === "error") finish(reject, new Error(data.message || "Worker処理に失敗しました。"));
      };
      worker.onerror = (event) => finish(reject, new Error(event.message || "Worker実行中にエラーが発生しました。"));
      try {
        worker.postMessage(payload, transferList);
      } catch (error) {
        finish(reject, error);
      }
    });
  }

  function withTimeout(promise, signal, deadline) {
    return new Promise((resolve, reject) => {
      if (signal.aborted) return reject(new Error("JOB_CANCELLED"));
      const remaining = deadline - Date.now();
      if (remaining <= 0) return reject(new Error("フォルダ走査が制限時間を超過しました。"));
      let settled = false;
      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal.removeEventListener("abort", onAbort);
        fn(value);
      };
      const timer = setTimeout(() => finish(reject, new Error("フォルダ走査が制限時間を超過しました。")), remaining);
      const onAbort = () => finish(reject, new Error("JOB_CANCELLED"));
      signal.addEventListener("abort", onAbort, { once: true });
      promise.then((value) => finish(resolve, value), (error) => finish(reject, error));
    });
  }

  function normalizeRootAndSubpaths(items, fallback = "project") {
    const cleaned = items.map((item) => ({
      relPath: String(item.relPath || item.file?.name || "").replace(/\\/g, "/").replace(/^\/+/, ""),
      file: item.file
    })).filter((item) => item.relPath && item.file);
    if (!cleaned.length) return { rootName: fallback, files: [] };
    const first = cleaned[0].relPath.split("/");
    if (first.length > 1) {
      const root = first[0];
      const prefix = `${root}/`;
      if (cleaned.every((item) => item.relPath.startsWith(prefix) && item.relPath.length > prefix.length)) {
        return { rootName: root, files: cleaned.map((item) => ({ relPath: item.relPath.slice(prefix.length), file: item.file })) };
      }
    }
    return { rootName: fallback, files: cleaned };
  }

  async function traverseEntries(entries, signal, deadline) {
    const files = [];
    let scanned = 0;
    const excluded = new Set([".git", ".svn", ".hg", "node_modules", "venv", ".venv", "env", "__pycache__", "build", "dist", "out", "target", ".idea", ".vscode", ".next"]);
    async function walk(entry, prefix, depth) {
      if (signal.aborted) throw new Error("JOB_CANCELLED");
      if (Date.now() > deadline) throw new Error("フォルダ走査が制限時間(20秒)を超過しました。");
      if (depth > 25) return;
      if (++scanned > MAX_ENTRIES) throw new Error(`フォルダ内のエントリ数が上限(${MAX_ENTRIES})を超えました。`);
      if (entry.isFile) {
        const file = await withTimeout(new Promise((resolve, reject) => entry.file(resolve, reject)), signal, deadline);
        if (file) files.push({ relPath: prefix + file.name, file });
      } else if (entry.isDirectory) {
        if (excluded.has(entry.name.toLowerCase())) return;
        const reader = entry.createReader();
        while (true) {
          const batch = await withTimeout(new Promise((resolve, reject) => reader.readEntries(resolve, reject)), signal, deadline);
          if (!batch.length) break;
          for (const child of batch) await walk(child, `${prefix}${entry.name}/`, depth + 1);
        }
      }
    }
    for (const entry of entries) await walk(entry, "", 0);
    return files;
  }

  async function traverseHandles(handles, signal, deadline) {
    const files = [];
    let scanned = 0;
    const excluded = new Set([".git", ".svn", ".hg", "node_modules", "venv", ".venv", "env", "__pycache__", "build", "dist", "out", "target", ".idea", ".vscode", ".next"]);
    async function walk(handle, prefix, depth) {
      if (signal.aborted) throw new Error("JOB_CANCELLED");
      if (Date.now() > deadline) throw new Error("フォルダ走査が制限時間(20秒)を超過しました。");
      if (depth > 25) return;
      if (++scanned > MAX_ENTRIES) throw new Error(`フォルダ内のエントリ数が上限(${MAX_ENTRIES})を超えました。`);
      if (handle.kind === "file") {
        const file = await handle.getFile();
        files.push({ relPath: prefix + file.name, file });
      } else if (handle.kind === "directory" && !excluded.has(handle.name.toLowerCase())) {
        for await (const [name, child] of handle.entries()) {
          await walk(child, `${prefix}${handle.name}/`, depth + 1);
        }
      }
    }
    for (const handle of handles) await walk(handle, "", 0);
    return files;
  }

  async function executePacking(items, rootName, existingJob = null, options = {}) {
    const job = existingJob || { abortController: new AbortController(), cancelWorker: null };
    currentJob = job;
    try {
      const payload = {
        mode: "files", rootName, files: items,
        options: { secretMode: el.secretMode.value, includeBoundary: el.boundary.value === "on" }
      };
      const result = await runWorker(payload, [], job);
      if (currentJob === job) currentJob = null;
      currentRootName = result.rootName || rootName || "project";
      updateStats(result.stats);
      const fullText = result.markdown || "";
      markdownBlob = new Blob([fullText], { type: "text/markdown;charset=utf-8" });
      el.preview.textContent = fullText.slice(0, PREVIEW_MAX_CHARS) +
        (fullText.length > PREVIEW_MAX_CHARS ? `\n\n…（残り ${(fullText.length - PREVIEW_MAX_CHARS).toLocaleString()} 文字。保存またはコピーで全文を取得できます）` : "");
      el.empty.hidden = true;
      el.preview.hidden = false;
      setIdle(true);
      setStatus(`Markdown生成完了：${result.stats?.processedFiles || 0}件のファイルを処理しました。`);
      for (const warning of (result.stats?.warnings || []).slice(0, 25)) appendLog(`保護・除外：${warning}`);
    } catch (error) {
      if (currentJob === job) currentJob = null;
      setIdle(false);
      if (error.message === "JOB_CANCELLED") setStatus("処理を中断し、作業メモリを解放しました。");
      else {
        setStatus(`処理に失敗しました：${error.message}`, true);
        appendLog(`処理エラー：${error.message}`);
      }
    }
  }

  async function handleZip(file) {
    if (file.size > MAX_ZIP_BYTES) return setStatus("ZIPファイルが上限50MBを超えているため読み込めません。", true);
    const job = { abortController: new AbortController(), cancelWorker: null };
    currentJob = job;
    setBusy(`ZIP「${file.name}」を検証しています…`);
    try {
      const buffer = await withTimeout(file.arrayBuffer(), job.abortController.signal, Date.now() + SCAN_TIMEOUT_MS);
      const result = await runWorker({
        mode: "zip", rootName: file.name.replace(/\.zip$/i, "") || "project", zipBuffer: buffer,
        options: { secretMode: el.secretMode.value, includeBoundary: el.boundary.value === "on" }
      }, [buffer], job);
      if (currentJob === job) currentJob = null;
      currentRootName = result.rootName || "project";
      updateStats(result.stats);
      const fullText = result.markdown || "";
      markdownBlob = new Blob([fullText], { type: "text/markdown;charset=utf-8" });
      el.preview.textContent = fullText.slice(0, PREVIEW_MAX_CHARS) +
        (fullText.length > PREVIEW_MAX_CHARS ? `\n\n…（残り ${(fullText.length - PREVIEW_MAX_CHARS).toLocaleString()} 文字）` : "");
      el.empty.hidden = true;
      el.preview.hidden = false;
      setIdle(true);
      setStatus(`Markdown生成完了：ZIPから${result.stats?.processedFiles || 0}件を処理しました。`);
      for (const warning of (result.stats?.warnings || []).slice(0, 25)) appendLog(`保護・除外：${warning}`);
    } catch (error) {
      if (currentJob === job) currentJob = null;
      setIdle(false);
      setStatus(error.message === "JOB_CANCELLED" ? "ZIP読込をキャンセルしました。" : `ZIP読込に失敗しました：${error.message}`, error.message !== "JOB_CANCELLED");
    }
  }

  async function handleMarkdown(file) {
    if (file.size > MAX_MD_BYTES) return setStatus("Markdownファイルが上限45MBを超えているため読み込めません。", true);
    const job = { abortController: new AbortController(), cancelWorker: null };
    currentJob = job;
    setBusy(`Markdown「${file.name}」から構造を復元しています…`);
    try {
      const textContent = await withTimeout(file.text(), job.abortController.signal, Date.now() + SCAN_TIMEOUT_MS);
      const result = await runWorker({ mode: "restore_zip", markdownText: textContent }, [], job);
      if (currentJob === job) currentJob = null;
      currentRootName = result.rootName || "restored_project";
      restoredZipBlob = new Blob([result.zipBuffer], { type: "application/zip" });
      markdownBlob = new Blob([textContent], { type: "text/markdown;charset=utf-8" });
      updateStats(result.stats, "復元");
      el.preview.textContent = `復元プレビュー：${currentRootName}/\n\n${result.treePreview || ""}\n\n${(result.fileSummaryLines || []).join("\n")}`;
      el.empty.hidden = true;
      el.preview.hidden = false;
      setIdle(true);
      setStatus(`復元準備完了：${result.stats?.restoredFiles || 0}件のファイルを検証しました。`);
      for (const warning of (result.stats?.warnings || [])) appendLog(`復元監査：${warning}`);
    } catch (error) {
      if (currentJob === job) currentJob = null;
      setIdle(false);
      setStatus(error.message === "JOB_CANCELLED" ? "復元処理をキャンセルしました。" : `Markdown復元に失敗しました：${error.message}`, error.message !== "JOB_CANCELLED");
    }
  }

  async function handleDroppedFiles(dataTransfer) {
    if (currentJob) return;
    const items = Array.from(dataTransfer.items || []);
    const files = Array.from(dataTransfer.files || []);
    if (!items.length && !files.length) {
      setStatus("ドロップされたデータを読み取れませんでした。ファイル選択ボタンをお使いください。", true);
      return;
    }

    if (files.length === 1 && (!items.length || !items[0].webkitGetAsEntry?.()?.isDirectory)) {
      const file = files[0];
      const name = file.name.toLowerCase();
      if (name.endsWith(".zip")) return handleZip(file);
      if (name.endsWith(".md") || name.endsWith(".markdown")) return handleMarkdown(file);
    }

    const job = { abortController: new AbortController(), cancelWorker: null };
    currentJob = job;
    setBusy("ドロップされたフォルダ・ファイルを確認しています…");
    try {
      const deadline = Date.now() + SCAN_TIMEOUT_MS;
      let collected = [];
      const handles = [];
      if (items.some((item) => typeof item.getAsFileSystemHandle === "function")) {
        for (const item of items) {
          if (item.kind === "file" && item.getAsFileSystemHandle) {
            try {
              const handle = await item.getAsFileSystemHandle();
              if (handle) handles.push(handle);
            } catch (_) { /* Browser fallback below. */ }
          }
        }
      }
      if (handles.length) {
        collected = await traverseHandles(handles, job.abortController.signal, deadline);
      } else {
        const entries = items.map((item) => item.webkitGetAsEntry?.()).filter(Boolean);
        if (entries.some((entry) => entry.isDirectory)) {
          collected = await traverseEntries(entries, job.abortController.signal, deadline);
        } else if (files.length) {
          collected = files.map((file) => ({ relPath: file.webkitRelativePath || file.name, file }));
        }
      }
      if (!collected.length) throw new Error("対応するファイルが見つかりません。ZIP・Markdown・フォルダを選択してください。");
      const fallbackRoot = entriesRootName(items) || "workspace";
      const normalized = normalizeRootAndSubpaths(collected, fallbackRoot);
      if (currentJob !== job) return;
      await executePacking(normalized.files, normalized.rootName, job);
    } catch (error) {
      if (currentJob === job) currentJob = null;
      setIdle(false);
      setStatus(error.message === "JOB_CANCELLED" ? "ドロップ処理をキャンセルしました。" : `ドロップを処理できませんでした：${error.message}`, error.message !== "JOB_CANCELLED");
    }
  }

  function entriesRootName(items) {
    for (const item of items) {
      const entry = item.webkitGetAsEntry?.();
      if (entry?.isDirectory) return entry.name;
    }
    return "";
  }

  function openPicker(input, label) {
    if (currentJob || !input) return;
    try {
      input.click();
    } catch (error) {
      setStatus(`${label}を開けませんでした。ブラウザのファイル選択権限をご確認ください。`, true);
      appendLog(`ファイル選択エラー：${error.message}`);
    }
  }

  el.selectFolder.addEventListener("click", () => openPicker(el.folderInput, "フォルダ選択"));
  el.selectZip.addEventListener("click", () => openPicker(el.zipInput, "ZIP選択"));
  el.selectMd.addEventListener("click", () => openPicker(el.mdInput, "Markdown選択"));

  el.folderInput.addEventListener("change", async () => {
    const list = Array.from(el.folderInput.files || []);
    el.folderInput.value = "";
    if (!list.length) return;
    if (list.length > MAX_ENTRIES) return setStatus(`選択ファイル数が上限${MAX_ENTRIES}件を超えています。`, true);
    const root = (list[0].webkitRelativePath || list[0].name).split("/")[0] || "project";
    const normalized = normalizeRootAndSubpaths(list.map((file) => ({ relPath: file.webkitRelativePath || file.name, file })), root);
    setBusy(`フォルダ「${root}」の${list.length}件を検査しています…`);
    await executePacking(normalized.files, normalized.rootName);
  });

  el.zipInput.addEventListener("change", () => {
    const file = el.zipInput.files?.[0];
    el.zipInput.value = "";
    if (file) handleZip(file);
  });
  el.mdInput.addEventListener("change", () => {
    const file = el.mdInput.files?.[0];
    el.mdInput.value = "";
    if (file) handleMarkdown(file);
  });

  el.dropZone.addEventListener("dragenter", (event) => {
    event.preventDefault();
    if (currentJob || !Array.from(event.dataTransfer?.types || []).includes("Files")) return;
    dragDepth++;
    el.dropZone.classList.add("dragover");
  });
  el.dropZone.addEventListener("dragover", (event) => {
    if (currentJob) return;
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = "copy";
    el.dropZone.classList.add("dragover");
  });
  el.dropZone.addEventListener("dragleave", (event) => {
    event.preventDefault();
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) el.dropZone.classList.remove("dragover");
  });
  el.dropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    dragDepth = 0;
    el.dropZone.classList.remove("dragover");
    if (!currentJob) handleDroppedFiles(event.dataTransfer);
  });

  el.reviewed.addEventListener("change", updateOutputButtons);
  el.cancel.addEventListener("click", () => cancelActiveJob());
  el.clearMemory.addEventListener("click", () => {
    releaseOutputMemory();
    updateStats(null);
    setStatus("出力データとプレビューを消去しました。");
  });
  el.clearLog.addEventListener("click", () => {
    el.log.textContent = "";
    el.logSection.hidden = true;
  });

  function downloadBlob(blob, filename) {
    revokeObjectUrl();
    activeObjectUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = activeObjectUrl;
    link.download = filename;
    link.hidden = true;
    document.body.appendChild(link);
    link.click();
    link.remove();
    const urlToRevoke = activeObjectUrl;
    activeObjectUrl = null;
    window.setTimeout(() => URL.revokeObjectURL(urlToRevoke), 30000);
  }

  el.copyMd.addEventListener("click", async () => {
    if (!markdownBlob || !el.reviewed.checked) return;
    try {
      await navigator.clipboard.writeText(await markdownBlob.text());
      setStatus("確認済みMarkdownをクリップボードにコピーしました。");
    } catch (error) {
      setStatus(`コピーに失敗しました：${error.message}`, true);
    }
  });
  el.downloadMd.addEventListener("click", () => {
    if (!markdownBlob || !el.reviewed.checked) return;
    const safe = currentRootName.replace(/[^a-zA-Z0-9_-]/g, "_") || "project";
    downloadBlob(markdownBlob, `${safe}_gemini_context.md`);
    setStatus(`${safe}_gemini_context.md の保存を開始しました。`);
  });

  async function ensureZipBlob() {
    if (restoredZipBlob) return restoredZipBlob;
    if (!markdownBlob) throw new Error("復元元のMarkdownがありません。");
    const result = await runWorker({ mode: "restore_zip", markdownText: await markdownBlob.text() });
    currentRootName = result.rootName || currentRootName;
    restoredZipBlob = new Blob([result.zipBuffer], { type: "application/zip" });
    return restoredZipBlob;
  }

  el.downloadZip.addEventListener("click", async () => {
    if (!el.reviewed.checked) return;
    try {
      const blob = await ensureZipBlob();
      const safe = currentRootName.replace(/[^a-zA-Z0-9_-]/g, "_") || "restored_project";
      downloadBlob(blob, `${safe}_restored.zip`);
      setStatus(`${safe}_restored.zip の保存を開始しました。`);
    } catch (error) {
      setStatus(`ZIP復元に失敗しました：${error.message}`, true);
    }
  });

  el.writeFolder.addEventListener("click", async () => {
    if (!el.reviewed.checked || !markdownBlob || typeof window.showDirectoryPicker !== "function") return;
    let parent;
    try {
      parent = await window.showDirectoryPicker({ mode: "readwrite" });
    } catch (error) {
      if (error.name === "AbortError") setStatus("フォルダ選択をキャンセルしました。");
      else setStatus(`フォルダを開けませんでした：${error.message}`, true);
      return;
    }
    try {
      setStatus("Markdownを検証し、選択したフォルダへ復元しています…");
      const result = await runWorker({ mode: "restore_files", markdownText: await markdownBlob.text() });
      const base = (result.rootName || "restored_project").replace(/[^a-zA-Z0-9._-]/g, "_") || "restored_project";
      let folderName = base;
      for (let suffix = 1; suffix < 1000; suffix++) {
        try {
          await parent.getDirectoryHandle(folderName);
          folderName = `${base}_${suffix}`;
        } catch (error) {
          if (error.name === "NotFoundError") break;
          throw error;
        }
      }
      const root = await parent.getDirectoryHandle(folderName, { create: true });
      for (const item of result.files) {
        const parts = item.relPath.split("/");
        let directory = root;
        for (const part of parts.slice(0, -1)) directory = await directory.getDirectoryHandle(part, { create: true });
        const handle = await directory.getFileHandle(parts[parts.length - 1], { create: true });
        const writable = await handle.createWritable({ keepExistingData: false });
        try {
          await writable.write(item.bytes);
          await writable.close();
        } catch (error) {
          await writable.abort().catch(() => {});
          throw error;
        }
      }
      setStatus(`復元完了：${folderName}/ に${result.files.length}件を書き込みました。`);
    } catch (error) {
      setStatus(`フォルダ復元に失敗しました：${error.message}`, true);
      appendLog(`フォルダ復元エラー：${error.message}`);
    }
  });

  el.selfTest.addEventListener("click", async () => {
    if (currentJob) return;
    setBusy("基本動作の自己診断を実行しています…");
    try {
      const file = new File(["export const test = true;\n"], "self-test.js", { type: "text/javascript" });
      const packed = await runWorker({
        mode: "files", rootName: "self_test", files: [{ relPath: "self-test.js", file }],
        options: { secretMode: "skip", includeBoundary: true }
      });
      const restored = await runWorker({ mode: "restore_zip", markdownText: packed.markdown });
      const passed = packed.stats.processedFiles === 1 && restored.stats.restoredFiles === 1;
      setIdle(false);
      setStatus(passed ? "自己診断に合格しました（Worker変換・ZIP復元の基本経路）。" : "自己診断に失敗しました。", !passed);
      appendLog(`基本自己診断：${passed ? "PASS" : "FAIL"}`);
    } catch (error) {
      setIdle(false);
      setStatus(`自己診断に失敗しました：${error.message}`, true);
    }
  });

  window.addEventListener("pagehide", () => {
    cancelActiveJob("PAGE_UNLOAD");
    releaseOutputMemory();
  });

  setIdle(false);
  setStatus("準備完了。ファイルを選択するか、上のエリアへドロップしてください。");
})();
