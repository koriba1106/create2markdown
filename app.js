"use strict";

(function () {
  // 1. Clickjacking (フレーム埋め込み) 検知・即時遮断
  if (window.self !== window.top) {
    const blockedEl = document.getElementById("frameBlocked");
    const appEl = document.getElementById("appRoot");
    if (blockedEl) blockedEl.hidden = false;
    if (appEl) appEl.hidden = true;
    throw new Error("FRAME_EMBEDDING_BLOCKED");
  }

  const MAX_LOG_LINES = 200;
  const MAX_FOLDER_SCAN_ENTRIES = 10000;
  const SCAN_TIMEOUT_MS = 20000;
  const PREVIEW_MAX_CHARS = 10000;

  // DOM要素の取得
  const dropZone = document.getElementById("dropZone");
  const dropTitle = document.getElementById("dropTitle");
  const folderInput = document.getElementById("folderInput");
  const zipInput = document.getElementById("zipInput");
  const secretModeSelect = document.getElementById("secretModeSelect");
  const boundarySelect = document.getElementById("boundarySelect");

  const btnSelectFolder = document.getElementById("btnSelectFolder");
  const btnSelectZip = document.getElementById("btnSelectZip");
  const btnSelfTest = document.getElementById("btnSelfTest");
  const btnClearMemory = document.getElementById("btnClearMemory");
  const btnCopy = document.getElementById("btnCopy");
  const btnDownload = document.getElementById("btnDownload");
  const btnCancel = document.getElementById("btnCancel");
  const btnClearLog = document.getElementById("btnClearLog");

  const confirmReviewedCheck = document.getElementById("confirmReviewedCheck");
  const statBadge = document.getElementById("statBadge");
  const metaInfo = document.getElementById("metaInfo");
  const emptyState = document.getElementById("emptyState");
  const previewBox = document.getElementById("previewBox");
  const statusBox = document.getElementById("statusBox");
  const logSection = document.getElementById("logSection");
  const logBox = document.getElementById("logBox");

  // 状態・メモリ管理用変数
  let currentJob = null;
  let resultBlob = null;       // 巨大文字列を保持せずBlobとして保持
  let activeObjectUrl = null;  // ObjectURLのリーク防止管理
  let currentRootName = "project";

  // ===================================================================
  // メモリ解放・クリーンアップ機構
  // ===================================================================
  function revokeActiveObjectUrl() {
    if (activeObjectUrl) {
      try {
        URL.revokeObjectURL(activeObjectUrl);
      } catch (_) {}
      activeObjectUrl = null;
    }
  }

  function releaseOutputMemory() {
    revokeActiveObjectUrl();
    resultBlob = null;
    currentRootName = "project";
    previewBox.textContent = "";
    previewBox.hidden = true;
    emptyState.hidden = false;
    confirmReviewedCheck.checked = false;
    confirmReviewedCheck.disabled = true;
    btnClearMemory.disabled = true;
    updateOutputButtonsState();
  }

  // ページ離脱・アンロード時に確実にメモリとWorkerを破棄
  window.addEventListener("pagehide", () => {
    cancelActiveJob("PAGE_UNLOAD");
    releaseOutputMemory();
  });

  // ===================================================================
  // UI更新ヘルパー
  // ===================================================================
  function setStatus(msg, isError = false) {
    statusBox.textContent = msg;
    statusBox.classList.toggle("error", Boolean(isError));
  }

  function appendLog(msg) {
    logSection.hidden = false;
    while (logBox.childNodes.length >= MAX_LOG_LINES) {
      logBox.removeChild(logBox.firstChild);
    }
    const line = document.createElement("div");
    line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    logBox.appendChild(line);
    logBox.scrollTop = logBox.scrollHeight;
  }

  function updateStatsSummary(stats) {
    if (!stats) {
      statBadge.textContent = "待機中";
      metaInfo.textContent = "まだファイルが読み込まれていません。";
      return;
    }
    const kb = ((stats.totalBytes || 0) / 1024).toFixed(1);
    const tokens = (stats.estimatedTokens || 0).toLocaleString();
    statBadge.textContent = `採用 ${stats.processedFiles || 0} 件 (${kb} KB)`;
    metaInfo.textContent =
      `走査: ${(stats.scannedEntries || 0).toLocaleString()}件 ｜ ` +
      `採用: ${(stats.processedFiles || 0).toLocaleString()}件 ｜ ` +
      `機密ファイル名除外: ${stats.secretFilesBlocked || 0}件 ｜ ` +
      `本文機密除外: ${stats.contentSecretSkipped || 0}件 ｜ ` +
      `マスク: ${stats.redactedSecretsCount || 0}箇所 ｜ ` +
      `推定トークン: 約${tokens}`;
  }

  function updateOutputButtonsState() {
    const canExport = Boolean(resultBlob) && confirmReviewedCheck.checked && !currentJob;
    btnCopy.disabled = !canExport;
    btnDownload.disabled = !canExport;
  }

  confirmReviewedCheck.addEventListener("change", updateOutputButtonsState);

  function setUIIdleState(keepOutput) {
    if (!keepOutput) {
      releaseOutputMemory();
      updateStatsSummary(null);
    } else {
      confirmReviewedCheck.disabled = false;
      btnClearMemory.disabled = false;
    }
    btnSelectFolder.disabled = false;
    btnSelectZip.disabled = false;
    btnSelfTest.disabled = false;
    btnCancel.disabled = true;
    dropZone.classList.remove("disabled");
    dropTitle.textContent = "📂 フォルダ または ZIPファイル をここにドロップ";
    updateOutputButtonsState();
  }

  function setUIBusyState(statusText) {
    releaseOutputMemory();
    statBadge.textContent = "処理中...";
    setStatus(statusText || "⏳ 安全に解析・検証しています...", false);

    btnSelectFolder.disabled = true;
    btnSelectZip.disabled = true;
    btnSelfTest.disabled = true;
    btnClearMemory.disabled = true;
    btnCancel.disabled = false;
    btnCopy.disabled = true;
    btnDownload.disabled = true;

    dropZone.classList.add("disabled");
    dropTitle.textContent = statusText || "⏳ 解析中...";
  }

  // ===================================================================
  // ジョブキャンセル・タイムアウト制御
  // ===================================================================
  function cancelActiveJob(reason = "JOB_CANCELLED") {
    if (!currentJob) return false;
    const job = currentJob;
    currentJob = null;
    if (job.abortController) {
      job.abortController.abort();
    }
    if (job.cancelWorkerPromise) {
      job.cancelWorkerPromise(new Error(reason));
    }
    return true;
  }

  function withAbortAndTimeout(promise, signal, deadline) {
    return new Promise((resolve, reject) => {
      if (signal.aborted) {
        reject(new Error("JOB_CANCELLED"));
        return;
      }
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        reject(new Error("フォルダ走査が制限時間(20秒)を超過しました。"));
        return;
      }

      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          signal.removeEventListener("abort", onAbort);
          reject(new Error("フォルダ走査が制限時間(20秒)を超過しました。"));
        }
      }, remaining);

      function onAbort() {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(new Error("JOB_CANCELLED"));
        }
      }

      signal.addEventListener("abort", onAbort, { once: true });

      promise.then(
        (val) => {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            signal.removeEventListener("abort", onAbort);
            resolve(val);
          }
        },
        (err) => {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            signal.removeEventListener("abort", onAbort);
            reject(err);
          }
        }
      );
    });
  }

  async function traverseDirectorySafely(entries, signal, deadline) {
    const collected = [];
    let scannedCount = 0;

    const excludeSet = new Set([
      ".git", ".svn", ".hg", "node_modules", "venv", ".venv", "env",
      "__pycache__", "build", "dist", "out", "target", ".idea", ".vscode", ".next"
    ]);

    async function walk(entry, pathPrefix, depth) {
      if (signal.aborted) throw new Error("JOB_CANCELLED");
      if (Date.now() > deadline) throw new Error("フォルダ走査が制限時間(20秒)を超過しました。");
      if (depth > 25) return;

      scannedCount++;
      if (scannedCount > MAX_FOLDER_SCAN_ENTRIES) {
        throw new Error(`フォルダ内の総エントリ数が上限(${MAX_FOLDER_SCAN_ENTRIES}件)を超えたため中断しました。`);
      }
      if (scannedCount % 150 === 0) {
        statBadge.textContent = `走査中: ${scannedCount.toLocaleString()}件`;
      }

      if (entry.isFile) {
        const fileObj = await withAbortAndTimeout(
          new Promise((resolve) => entry.file(resolve, () => resolve(null))),
          signal,
          deadline
        );
        if (fileObj) {
          collected.push({ relPath: pathPrefix + fileObj.name, file: fileObj });
        }
      } else if (entry.isDirectory) {
        if (excludeSet.has(entry.name.toLowerCase())) return;
        const reader = entry.createReader();
        while (true) {
          const batch = await withAbortAndTimeout(
            new Promise((resolve) => reader.readEntries(resolve, () => resolve([]))),
            signal,
            deadline
          );
          if (!batch || batch.length === 0) break;
          for (const child of batch) {
            await walk(child, `${pathPrefix}${entry.name}/`, depth + 1);
          }
        }
      }
    }

    for (const rootEntry of entries) {
      await walk(rootEntry, "", 0);
    }
    return collected;
  }

  // ===================================================================
  // Worker 実行と厳格なリソース解放
  // ===================================================================
  function runWorkerTask(payload, transferList = [], jobContext = null) {
    return new Promise((resolve, reject) => {
      let settled = false;
      let worker = null;

      try {
        worker = new Worker("./worker.js");
      } catch (_) {
        reject(new Error("Workerの起動に失敗しました（ローカル実行時はHTTPサーバー経由で開いてください）。"));
        return;
      }

      function finalize() {
        if (worker) {
          worker.onmessage = null;
          worker.onerror = null;
          worker.terminate();
          worker = null;
        }
        if (jobContext && jobContext.cancelWorkerPromise) {
          jobContext.cancelWorkerPromise = null;
        }
      }

      function settleResolve(val) {
        if (settled) return;
        settled = true;
        finalize();
        resolve(val);
      }

      function settleReject(err) {
        if (settled) return;
        settled = true;
        finalize();
        reject(err);
      }

      if (jobContext) {
        if (jobContext.abortController && jobContext.abortController.signal.aborted) {
          settleReject(new Error("JOB_CANCELLED"));
          return;
        }
        jobContext.cancelWorkerPromise = settleReject;
      }

      worker.onmessage = (e) => {
        if (settled) return;
        const data = e.data;
        if (data.type === "progress") {
          updateStatsSummary(data.stats);
        } else if (data.type === "complete") {
          settleResolve(data);
        } else if (data.type === "error") {
          settleReject(new Error(data.message));
        }
      };

      worker.onerror = (err) => {
        settleReject(new Error(err.message || "Worker実行中にエラーが発生しました。"));
      };

      worker.postMessage(payload, transferList);
    });
  }

  async function executePackingJob(payload, transferList = [], existingJob = null) {
    const job = existingJob || { abortController: new AbortController(), cancelWorkerPromise: null };
    currentJob = job;

    try {
      payload.options = {
        secretMode: secretModeSelect.value,
        includeBoundary: boundarySelect.value === "on"
      };

      let result = await runWorkerTask(payload, transferList, job);
      if (currentJob === job) {
        currentJob = null;
      }

      currentRootName = result.rootName || "project";
      updateStatsSummary(result.stats);

      // 省メモリ設計: 長大な文字列は即座にBlobへ変換し、文字列参照(result.markdown)を破棄してGC対象にする
      const totalChars = result.markdown.length;
      const previewSlice = result.markdown.slice(0, PREVIEW_MAX_CHARS);
      resultBlob = new Blob([result.markdown], { type: "text/markdown;charset=utf-8" });
      result.markdown = ""; // 文字列参照を即座に切る

      emptyState.hidden = true;
      previewBox.hidden = false;
      previewBox.textContent =
        previewSlice +
        (totalChars > PREVIEW_MAX_CHARS
          ? `\n\n... (以降 ${(totalChars - PREVIEW_MAX_CHARS).toLocaleString()} 文字省略。保存またはコピーで全文を取得できます)`
          : "");

      setUIIdleState(true);
      setStatus(`✅ 解析完了: ${result.stats.processedFiles}件のファイルを安全にパックしました。`, false);

      if (result.stats.warnings && result.stats.warnings.length > 0) {
        appendLog(`🛡️ 保護・除外ログ (${result.stats.warnings.length}件):`);
        for (const w of result.stats.warnings.slice(0, 25)) {
          appendLog(`  ・${w}`);
        }
        if (result.stats.warnings.length > 25) {
          appendLog(`  ...他 ${result.stats.warnings.length - 25} 件の除外ログ`);
        }
      }
      result = null;
    } catch (err) {
      if (currentJob === job) {
        currentJob = null;
      }
      setUIIdleState(false);
      if (err.message === "JOB_CANCELLED") {
        setStatus("🛑 処理を中断し、Workerおよびメモリを解放しました。", false);
      } else {
        setStatus(`❌ エラー: ${err.message}`, true);
        appendLog(`❌ 中断・エラー: ${err.message}`);
      }
    }
  }

  async function handleZipFile(file) {
    if (file.size > 50 * 1024 * 1024) {
      setStatus("❌ ZIP圧縮サイズが上限(50MB)を超えているため拒否しました。", true);
      return;
    }
    const rootName = file.name.replace(/\.zip$/i, "");
    setUIBusyState(`⏳ ZIP (${file.name}) の構造・CRC-32・ストリーム検証中...`);

    const job = { abortController: new AbortController(), cancelWorkerPromise: null };
    currentJob = job;

    try {
      const zipBuffer = await withAbortAndTimeout(
        file.arrayBuffer(),
        job.abortController.signal,
        Date.now() + SCAN_TIMEOUT_MS
      );
      // zipBufferをTransferableとしてWorkerへ完全移譲（メインスレッド側のメモリ消費をゼロ化）
      await executePackingJob({ mode: "zip", rootName, zipBuffer }, [zipBuffer], job);
    } catch (err) {
      if (currentJob === job) currentJob = null;
      setUIIdleState(false);
      if (err.message === "JOB_CANCELLED") {
        setStatus("🛑 ZIP読込をキャンセルしました。", false);
      } else {
        setStatus(`❌ ZIP読込失敗: ${err.message}`, true);
      }
    }
  }

  // ===================================================================
  // イベントリスナー登録
  // ===================================================================
  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    if (!currentJob) dropZone.classList.add("dragover");
  });

  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));

  dropZone.addEventListener("drop", async (e) => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    if (currentJob) return;

    const items = e.dataTransfer.items;
    if (!items || items.length === 0) return;

    if (items.length === 1) {
      const singleFile = items[0].getAsFile();
      if (singleFile && singleFile.name.toLowerCase().endsWith(".zip")) {
        await handleZipFile(singleFile);
        return;
      }
    }

    const entries = [];
    for (let i = 0; i < items.length; i++) {
      const entry = items[i].webkitGetAsEntry ? items[i].webkitGetAsEntry() : null;
      if (entry) entries.push(entry);
    }
    if (entries.length === 0) return;

    setUIBusyState("⏳ フォルダ階層を走査中...");
    const job = { abortController: new AbortController(), cancelWorkerPromise: null };
    currentJob = job;

    try {
      let allFiles = await traverseDirectorySafely(
        entries,
        job.abortController.signal,
        Date.now() + SCAN_TIMEOUT_MS
      );

      const rootName = entries.length === 1 ? entries[0].name : "workspace";
      if (entries.length === 1 && entries[0].isDirectory) {
        const prefix = entries[0].name + "/";
        allFiles = allFiles.map((item) => ({
          relPath: item.relPath.startsWith(prefix) ? item.relPath.slice(prefix.length) : item.relPath,
          file: item.file
        }));
      }

      setStatus("⏳ Workerでファイル内容と機密情報を検査中...", false);
      await executePackingJob({ mode: "files", rootName, files: allFiles }, [], job);
    } catch (err) {
      if (currentJob === job) currentJob = null;
      setUIIdleState(false);
      if (err.message === "JOB_CANCELLED") {
        setStatus("🛑 フォルダ走査をキャンセルしました。", false);
      } else {
        setStatus(`❌ 走査中断: ${err.message}`, true);
      }
    }
  });

  dropZone.addEventListener("click", (e) => {
    if (currentJob) return;
    if (e.target === folderInput || e.target === zipInput) return;
    folderInput.click();
  });

  dropZone.addEventListener("keydown", (e) => {
    if (currentJob) return;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      folderInput.click();
    }
  });

  btnSelectFolder.addEventListener("click", () => folderInput.click());
  btnSelectZip.addEventListener("click", () => zipInput.click());

  folderInput.addEventListener("change", async (e) => {
    const rawList = e.target.files;
    if (!rawList || rawList.length === 0) return;

    if (rawList.length > MAX_FOLDER_SCAN_ENTRIES) {
      setStatus(`❌ 選択ファイル数(${rawList.length}件)が走査上限(${MAX_FOLDER_SCAN_ENTRIES}件)を超えています。`, true);
      folderInput.value = "";
      return;
    }

    const firstPath = rawList[0].webkitRelativePath || rawList[0].name;
    const rootName = firstPath.includes("/") ? firstPath.split("/")[0] : "project";
    const prefix = rootName + "/";

    const files = [];
    for (let i = 0; i < rawList.length; i++) {
      const f = rawList[i];
      const rawRel = f.webkitRelativePath || f.name;
      files.push({
        relPath: rawRel.startsWith(prefix) ? rawRel.slice(prefix.length) : rawRel,
        file: f
      });
    }
    folderInput.value = "";

    setUIBusyState(`⏳ フォルダ (${rootName}: ${files.length}件) を検査中...`);
    await executePackingJob({ mode: "files", rootName, files });
  });

  zipInput.addEventListener("change", async (e) => {
    const file = e.target.files && e.target.files[0];
    zipInput.value = "";
    if (file) await handleZipFile(file);
  });

  btnCancel.addEventListener("click", () => {
    cancelActiveJob("JOB_CANCELLED");
  });

  btnClearMemory.addEventListener("click", () => {
    releaseOutputMemory();
    updateStatsSummary(null);
    setStatus("🧹 出力データとプレビューメモリを完全に解放しました。", false);
  });

  btnClearLog.addEventListener("click", () => {
    logBox.textContent = "";
    logSection.hidden = true;
  });

  btnCopy.addEventListener("click", async () => {
    if (!resultBlob || !confirmReviewedCheck.checked) return;
    try {
      const text = await resultBlob.text();
      await navigator.clipboard.writeText(text);
      setStatus("📋 確認済みMarkdownをクリップボードにコピーしました。", false);
    } catch (err) {
      setStatus(`❌ コピー失敗: ${err.message}`, true);
    }
  });

  btnDownload.addEventListener("click", () => {
    if (!resultBlob || !confirmReviewedCheck.checked) return;
    revokeActiveObjectUrl();
    const safeName = currentRootName.replace(/[^a-zA-Z0-9_-]/g, "_") || "project";
    activeObjectUrl = URL.createObjectURL(resultBlob);

    const a = document.createElement("a");
    a.href = activeObjectUrl;
    a.download = `${safeName}_gemini_context.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

    // ダウンロード開始後、10秒で確実にURL参照を解放
    setTimeout(revokeActiveObjectUrl, 10000);
    setStatus(`💾 ${safeName}_gemini_context.md を保存しました。`, false);
  });

  // ===================================================================
  // 全12項目の厳格セキュリティ自己診断スイート
  // ===================================================================
  const TEST_CRC_TABLE = (() => {
    const table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      table[i] = c >>> 0;
    }
    return table;
  })();

  function testCrc32(bytes) {
    let crc = 0xffffffff;
    for (let i = 0; i < bytes.byteLength; i++) {
      crc = TEST_CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
    }
    return (crc ^ 0xffffffff) >>> 0;
  }

  async function deflateRawBytes(uint8Data) {
    const cs = new CompressionStream("deflate-raw");
    const writer = cs.writable.getWriter();
    writer.write(uint8Data);
    writer.close();
    const reader = cs.readable.getReader();
    const chunks = [];
    let len = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      chunks.push(value);
      len += value.byteLength;
    }
    const out = new Uint8Array(len);
    let offset = 0;
    for (const c of chunks) {
      out.set(c, offset);
      offset += c.byteLength;
    }
    return out;
  }

  function buildCustomTestZip(entries, options = {}) {
    const encoder = new TextEncoder();
    const localParts = [];
    const cdParts = [];
    let offset = 0;

    for (const item of entries) {
      const cdNameBytes = encoder.encode(item.name);
      const lfhNameBytes = encoder.encode(item.lfhName !== undefined ? item.lfhName : item.name);
      const rawData = item.data instanceof Uint8Array ? item.data : encoder.encode(item.data);
      const compData = item.compressedData || rawData;
      const method = item.method !== undefined ? item.method : 0;
      const crc = item.customCrc !== undefined ? item.customCrc : testCrc32(rawData);
      const uncompLen = item.fakeUncompSize !== undefined ? item.fakeUncompSize : rawData.byteLength;
      const compLen = compData.byteLength;
      const myLhOffset = item.forceLhOffset !== undefined ? item.forceLhOffset : offset;

      if (!item.skipLocalHeaderWrite) {
        const lh = new Uint8Array(30 + lfhNameBytes.byteLength);
        const lhv = new DataView(lh.buffer);
        lhv.setUint32(0, 0x04034b50, true);
        lhv.setUint16(4, 20, true);
        lhv.setUint16(6, 0, true);
        lhv.setUint16(8, method, true);
        lhv.setUint32(14, crc, true);
        lhv.setUint32(18, compLen, true);
        lhv.setUint32(22, uncompLen, true);
        lhv.setUint16(26, lfhNameBytes.byteLength, true);
        lh.set(lfhNameBytes, 30);

        localParts.push(lh, compData);
        offset += lh.byteLength + compData.byteLength;
      }

      const cd = new Uint8Array(46 + cdNameBytes.byteLength);
      const cdv = new DataView(cd.buffer);
      cdv.setUint32(0, 0x02014b50, true);
      cdv.setUint16(4, 20, true);
      cdv.setUint16(6, 20, true);
      cdv.setUint16(8, 0, true);
      cdv.setUint16(10, method, true);
      cdv.setUint32(16, crc, true);
      cdv.setUint32(20, compLen, true);
      cdv.setUint32(24, uncompLen, true);
      cdv.setUint16(28, cdNameBytes.byteLength, true);
      cdv.setUint32(42, myLhOffset, true);
      cd.set(cdNameBytes, 46);

      cdParts.push(cd);
    }

    const cdStart = offset;
    let cdSize = 0;
    for (const c of cdParts) cdSize += c.byteLength;
    const declaredCdSize = options.corruptCdSize !== undefined ? options.corruptCdSize : cdSize;

    const eocd = new Uint8Array(22);
    const eocdv = new DataView(eocd.buffer);
    eocdv.setUint32(0, 0x06054b50, true);
    eocdv.setUint16(8, entries.length, true);
    eocdv.setUint16(10, entries.length, true);
    eocdv.setUint32(12, declaredCdSize, true);
    eocdv.setUint32(16, cdStart, true);

    const out = new Uint8Array(cdStart + cdSize + 22);
    let ptr = 0;
    for (const p of localParts) { out.set(p, ptr); ptr += p.byteLength; }
    for (const p of cdParts) { out.set(p, ptr); ptr += p.byteLength; }
    out.set(eocd, ptr);
    return out.buffer;
  }

  btnSelfTest.addEventListener("click", async () => {
    if (currentJob) return;
    logBox.textContent = "";
    setUIBusyState("🧪 厳格セキュリティ自己診断 (12項目) を実行中...");
    appendLog("=== 🧪 厳格セキュリティ自己診断スイート (全12項目) 開始 ===");

    const results = [];
    async function expectReject(testName, zipBuf, expectedSubstr) {
      try {
        await runWorkerTask({ mode: "zip", rootName: "test", zipBuffer: zipBuf }, [zipBuf]);
        results.push({ name: testName, pass: false, detail: "拒否されず通過" });
      } catch (err) {
        const matched = !expectedSubstr || err.message.includes(expectedSubstr);
        results.push({ name: testName, pass: matched, detail: err.message });
      }
    }

    try {
      const badCdZip = buildCustomTestZip([{ name: "a.py", data: "x=1" }], { corruptCdSize: 99999 });
      await expectReject("1. Central Directory 境界逸脱の拒否", badCdZip, "Central Directory");

      const mismatchZip = buildCustomTestZip([{ name: "safe.py", lfhName: "evil.py", data: "x=1" }]);
      await expectReject("2. LFH/CD ヘッダ不整合の拒否", mismatchZip, "矛盾");

      const overlapZip = buildCustomTestZip([
        { name: "a.py", data: "print(1)" },
        { name: "b.py", data: "print(1)", forceLhOffset: 0, skipLocalHeaderWrite: true }
      ]);
      await expectReject("3. エントリ領域重複(Overlap)の拒否", overlapZip, "Overlap");

      const badCrcZip = buildCustomTestZip([{ name: "corrupt.py", data: "print('hello')", customCrc: 0x12345678 }]);
      await expectReject("4. CRC-32 不一致（改ざん）の拒否", badCrcZip, "CRC_MISMATCH");

      const bombPayload = new Uint8Array(20 * 1024).fill(65);
      const compressedBomb = await deflateRawBytes(bombPayload);
      const mainSuitZip = buildCustomTestZip([
        { name: "src/spoofed_bomb.py", data: bombPayload, compressedData: compressedBomb, method: 8, fakeUncompSize: 64 },
        { name: "../../etc/passwd.py", data: "print('zip_slip')" },
        { name: ".env.local", data: "SECRET=1" },
        { name: "src/unquoted_secrets.py", data: "password = my-secret-value\nAPI_KEY=example-secret-value\n# Authorization: Bearer example-token\n" },
        { name: "src/__proto__/constructor.py", data: "ok = True" },
        { name: "src/back`tick``name.py", data: "val = 1" },
        { name: "src/fence.md", data: "Doc\n```js\nconsole.log(1);\n```\n" }
      ]);

      const suitRes = await runWorkerTask(
        {
          mode: "zip",
          rootName: "suit_test",
          zipBuffer: mainSuitZip,
          options: {
            secretMode: "redact",
            includeBoundary: true,
            customLimits: { MAX_SINGLE_FILE_BYTES: 10 * 1024 }
          }
        },
        [mainSuitZip]
      );

      const md = suitRes.markdown;
      results.push({
        name: "5. ヘッダ偽装Deflate Zip Bombの実ストリーム遮断",
        pass: !md.includes("spoofed_bomb.py") && suitRes.stats.warnings.some((w) => w.includes("Zip Bomb防御")),
        detail: "10KB超過時点でストリーム即時破棄"
      });
      results.push({
        name: "6. Zip Slip (../../) パストラバーサル遮断",
        pass: !md.includes("zip_slip") && !md.includes("passwd"),
        detail: "不正相対パスを拒否"
      });
      results.push({
        name: "7. 引用符なし秘密情報・Bearerトークンの検出とマスク",
        pass: !md.includes("my-secret-value") && !md.includes("example-secret-value") && !md.includes("example-token") && suitRes.stats.redactedSecretsCount >= 3,
        detail: `${suitRes.stats.redactedSecretsCount}箇所を捕捉`
      });
      results.push({
        name: "8. 機密ファイル名 (.env.local) の除外",
        pass: !md.includes("SECRET=1") && suitRes.stats.secretFilesBlocked >= 1,
        detail: "ブラックリストにより除外"
      });
      results.push({
        name: "9. __proto__ / constructor 特殊名の安全ツリー構築",
        pass: md.includes("📁 __proto__/") && md.includes("📄 constructor.py"),
        detail: "Map/Setによるプロトタイプ汚染防止"
      });
      results.push({
        name: "10. バッククォートを含むファイル名のコードスパン保護",
        pass: md.includes("```src/back`tick``name.py```"),
        detail: "CommonMark準拠エスケープ"
      });
      results.push({
        name: "11. 本文内3連バッククォートに対する動的4連フェンス生成",
        pass: md.includes("````md"),
        detail: "Markdown構造破壊を防止"
      });

      const budgetZip = buildCustomTestZip([
        { name: "f1.py", data: "A".repeat(4000) },
        { name: "f2.py", data: "B".repeat(4000) },
        { name: "f3.py", data: "C".repeat(4000) }
      ]);
      const budgetRes = await runWorkerTask(
        {
          mode: "zip",
          rootName: "budget_test",
          zipBuffer: budgetZip,
          options: { customLimits: { MAX_TOTAL_DECOMPRESSED_BYTES: 8500 } }
        },
        [budgetZip]
      );
      const budgetPassed = budgetRes.stats.processedFiles === 2;

      const cancelJobCtx = { abortController: new AbortController(), cancelWorkerPromise: null };
      const dummyZip = buildCustomTestZip([{ name: "ok.py", data: "x = 1" }]);
      const pendingPromise = runWorkerTask({ mode: "zip", rootName: "cancel_test", zipBuffer: dummyZip }, [dummyZip], cancelJobCtx);
      cancelJobCtx.cancelWorkerPromise(new Error("JOB_CANCELLED"));
      let cancelSettled = false;
      try {
        await pendingPromise;
      } catch (cErr) {
        if (cErr.message === "JOB_CANCELLED") cancelSettled = true;
      }

      results.push({
        name: "12. 総展開バジェット上限停止 ＆ キャンセル時リソース即時解放",
        pass: budgetPassed && cancelSettled,
        detail: `バジェット停止=${budgetPassed}, キャンセル即時決済=${cancelSettled}`
      });

      let allPassed = true;
      for (const r of results) {
        appendLog(`${r.pass ? "✅ PASS" : "❌ FAIL"} : ${r.name} (${r.detail})`);
        if (!r.pass) allPassed = false;
      }

      setUIIdleState(false);
      setStatus(
        allPassed
          ? "🎉 全12項目の厳格セキュリティ自己診断にすべて合格しました。"
          : "⚠️ 一部の自己診断項目が失敗しました。ログを確認してください。",
        !allPassed
      );
    } catch (err) {
      setUIIdleState(false);
      setStatus(`❌ 自己診断エラー: ${err.message}`, true);
    }
  });
})();