"use strict";

(function () {
  const MAX_LOG_LINES = 300;
  const MAX_FOLDER_SCAN_ENTRIES = 10000;
  const SCAN_TIMEOUT_MS = 20000;

  const dropZone = document.getElementById("dropZone");
  const dropTitle = document.getElementById("dropTitle");
  const folderInput = document.getElementById("folderInput");
  const zipInput = document.getElementById("zipInput");
  const secretModeSelect = document.getElementById("secretModeSelect");
  const boundaryCheck = document.getElementById("boundaryCheck");

  const btnSelectFolder = document.getElementById("btnSelectFolder");
  const btnSelectZip = document.getElementById("btnSelectZip");
  const btnSelfTest = document.getElementById("btnSelfTest");
  const btnCopy = document.getElementById("btnCopy");
  const btnDownload = document.getElementById("btnDownload");
  const btnCancel = document.getElementById("btnCancel");
  const btnClearLog = document.getElementById("btnClearLog");

  const confirmReviewedCheck = document.getElementById("confirmReviewedCheck");
  const previewBox = document.getElementById("previewBox");
  const progressBar = document.getElementById("progressBar");
  const logBox = document.getElementById("logBox");

  const statScanned = document.getElementById("statScanned");
  const statFiles = document.getElementById("statFiles");
  const statSecretFiles = document.getElementById("statSecretFiles");
  const statContentSkipped = document.getElementById("statContentSkipped");
  const statRedacted = document.getElementById("statRedacted");
  const statBytes = document.getElementById("statBytes");

  // 修正P1 (セクション4): ジョブとPromiseのライフサイクルを一元管理するオブジェクト
  let currentJob = null;
  let generatedMarkdown = "";
  let currentRootName = "project";

  function appendLog(msg) {
    while (logBox.childNodes.length >= MAX_LOG_LINES) {
      logBox.removeChild(logBox.firstChild);
    }
    const line = document.createElement("div");
    line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    logBox.appendChild(line);
    logBox.scrollTop = logBox.scrollHeight;
  }

  function resetStatsUI() {
    statScanned.textContent = "0";
    statFiles.textContent = "0";
    statSecretFiles.textContent = "0";
    statContentSkipped.textContent = "0";
    statRedacted.textContent = "0";
    statBytes.textContent = "0 KB";
  }

  function updateStatsUI(stats) {
    if (!stats) return;
    statScanned.textContent = `${(stats.scannedEntries || 0).toLocaleString()} 件`;
    statFiles.textContent = `${(stats.processedFiles || 0).toLocaleString()} 件`;
    statSecretFiles.textContent = `${(stats.secretFilesBlocked || 0).toLocaleString()} 件`;
    statContentSkipped.textContent = `${(stats.contentSecretSkipped || 0).toLocaleString()} 件`;
    statRedacted.textContent = `${(stats.redactedSecretsCount || 0).toLocaleString()} 箇所`;
    statBytes.textContent = `${((stats.totalBytes || 0) / 1024).toFixed(1)} KB`;
  }

  function updateOutputButtonsState() {
    const canExport = Boolean(generatedMarkdown) && confirmReviewedCheck.checked && !currentJob;
    btnCopy.disabled = !canExport;
    btnDownload.disabled = !canExport;
  }

  confirmReviewedCheck.addEventListener("change", updateOutputButtonsState);

  function setUIIdleState(keepOutput) {
    if (!keepOutput) {
      generatedMarkdown = "";
      previewBox.value = "";
      confirmReviewedCheck.checked = false;
      confirmReviewedCheck.disabled = true;
    } else {
      confirmReviewedCheck.disabled = false;
    }
    btnSelectFolder.disabled = false;
    btnSelectZip.disabled = false;
    btnSelfTest.disabled = false;
    btnCancel.disabled = true;
    updateOutputButtonsState();

    dropZone.classList.remove("disabled");
    progressBar.classList.remove("indeterminate");
    progressBar.style.width = generatedMarkdown ? "100%" : "0%";
    dropTitle.textContent = "📂 ここにフォルダ または ZIPファイル をドラッグ＆ドロップ";
  }

  function setUIBusyState(statusText) {
    generatedMarkdown = "";
    previewBox.value = "";
    confirmReviewedCheck.checked = false;
    confirmReviewedCheck.disabled = true;
    resetStatsUI();

    btnSelectFolder.disabled = true;
    btnSelectZip.disabled = true;
    btnSelfTest.disabled = true;
    btnCancel.disabled = false;
    btnCopy.disabled = true;
    btnDownload.disabled = true;

    dropZone.classList.add("disabled");
    progressBar.classList.add("indeterminate");
    dropTitle.textContent = statusText || "⏳ 安全に解析・処理中...";
  }

  // 修正P1 (セクション4): キャンセル時に待機中のPromiseも確実にrejectしてリソースを解放
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

  // 修正P1 (セクション5-①): 非同期APIが応答しない場合でも期限・Abort時に即時脱出するラッパー
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
      if (scannedCount % 100 === 0) {
        statScanned.textContent = `${scannedCount.toLocaleString()} 件 (走査中)`;
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

  // 修正P1 (セクション4): 正常完了・エラー・キャンセルで必ず一度だけSettleするWorker実行器
  function runWorkerTask(payload, transferList = [], jobContext = null) {
    return new Promise((resolve, reject) => {
      let settled = false;
      let worker = null;

      try {
        worker = new Worker("./worker.js");
      } catch (err) {
        reject(new Error("Workerの起動に失敗しました（ローカル確認時はHTTPサーバー経由で開いてください）。"));
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
          updateStatsUI(data.stats);
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
        includeBoundary: boundaryCheck.checked
      };
      const result = await runWorkerTask(payload, transferList, job);
      if (currentJob === job) {
        currentJob = null;
      }

      generatedMarkdown = result.markdown;
      currentRootName = result.rootName || "project";
      updateStatsUI(result.stats);

      // 出力前プレビューの表示（先頭10,000文字）
      const previewSlice = generatedMarkdown.slice(0, 10000);
      previewBox.value =
        previewSlice +
        (generatedMarkdown.length > 10000
          ? `\n\n... (以降 ${generatedMarkdown.length - 10000} 文字省略。全体は保存またはコピーで取得できます)`
          : "");

      setUIIdleState(true);

      appendLog(
        `✅ 完了: 採用=${result.stats.processedFiles}件 / ファイル名除外=${result.stats.secretFilesBlocked}件 / 本文機密除外=${result.stats.contentSecretSkipped}件 / 本文マスク=${result.stats.redactedSecretsCount}箇所`
      );
      appendLog("🔎 プレビュー枠で内容を確認し、チェックボックスをONにするとコピー・保存が可能になります。");

      for (const w of result.stats.warnings.slice(0, 20)) {
        appendLog(`  🛡️ ${w}`);
      }
      if (result.stats.warnings.length > 20) {
        appendLog(`  ...他 ${result.stats.warnings.length - 20} 件の保護ログ`);
      }
    } catch (err) {
      if (currentJob === job) {
        currentJob = null;
      }
      setUIIdleState(false);
      if (err.message === "JOB_CANCELLED") {
        appendLog("🛑 処理をキャンセルし、Worker・待機Promise・メモリを解放しました。");
      } else {
        appendLog(`❌ 中断・エラー: ${err.message}`);
      }
    }
  }

  async function handleZipFile(file) {
    if (file.size > 25 * 1024 * 1024) {
      appendLog("❌ ZIP圧縮サイズが上限(25MB)を超えているため拒否しました。");
      return;
    }
    const rootName = file.name.replace(/\.zip$/i, "");
    setUIBusyState(`⏳ ZIP (${file.name}) の構造・CRC・ストリーム検証中...`);
    appendLog(`▶ ZIPアーカイブ (${file.name}) の検査を開始...`);

    const job = { abortController: new AbortController(), cancelWorkerPromise: null };
    currentJob = job;

    try {
      const zipBuffer = await withAbortAndTimeout(
        file.arrayBuffer(),
        job.abortController.signal,
        Date.now() + SCAN_TIMEOUT_MS
      );
      await executePackingJob({ mode: "zip", rootName, zipBuffer }, [zipBuffer], job);
    } catch (err) {
      if (currentJob === job) currentJob = null;
      setUIIdleState(false);
      appendLog(err.message === "JOB_CANCELLED" ? "🛑 ZIP読込をキャンセルしました。" : `❌ ZIP読込失敗: ${err.message}`);
    }
  }

  // ドロップ＆ファイル選択イベント
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

    setUIBusyState("⏳ フォルダ階層を走査中 (キャンセル可能)...");
    appendLog("▶ フォルダ走査を開始...");
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

      dropTitle.textContent = "⏳ Workerでファイル内容と機密情報を検査中...";
      await executePackingJob({ mode: "files", rootName, files: allFiles }, [], job);
    } catch (err) {
      if (currentJob === job) currentJob = null;
      setUIIdleState(false);
      appendLog(err.message === "JOB_CANCELLED" ? "🛑 フォルダ走査をキャンセルしました。" : `❌ 走査中断: ${err.message}`);
    }
  });

  btnSelectFolder.addEventListener("click", () => folderInput.click());
  btnSelectZip.addEventListener("click", () => zipInput.click());
  dropZone.addEventListener("click", () => {
    if (!currentJob) folderInput.click();
  });

  folderInput.addEventListener("change", async (e) => {
    const rawList = e.target.files;
    if (!rawList || rawList.length === 0) return;

    if (rawList.length > MAX_FOLDER_SCAN_ENTRIES) {
      appendLog(`❌ 選択されたファイル数(${rawList.length}件)が走査上限(${MAX_FOLDER_SCAN_ENTRIES}件)を超えています。`);
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

    setUIBusyState(`⏳ フォルダ (${rootName}) を検査中...`);
    appendLog(`▶ フォルダ (${rootName}: ${files.length}件) の処理を開始...`);
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

  btnClearLog.addEventListener("click", () => {
    logBox.textContent = "";
  });

  btnCopy.addEventListener("click", async () => {
    if (!generatedMarkdown || !confirmReviewedCheck.checked) return;
    try {
      await navigator.clipboard.writeText(generatedMarkdown);
      appendLog("📋 確認済みMarkdownをクリップボードにコピーしました。");
    } catch (err) {
      appendLog(`❌ コピー失敗: ${err.message}`);
    }
  });

  btnDownload.addEventListener("click", () => {
    if (!generatedMarkdown || !confirmReviewedCheck.checked) return;
    const safeName = currentRootName.replace(/[^a-zA-Z0-9_-]/g, "_") || "project";
    const blob = new Blob([generatedMarkdown], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${safeName}_gemini_context.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    appendLog(`💾 ${safeName}_gemini_context.md のダウンロードを開始しました。`);
  });

  // ===================================================================
  // 修正P1 (セクション6): 厳格化された全12項目のセキュリティ自己診断スイート
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
    setUIBusyState("🧪 厳格セキュリティ自己診断 (12項目) を実行中...");
    appendLog("=== 🧪 厳格セキュリティ自己診断スイート (全12項目) 開始 ===");

    const results = [];
    async function expectReject(testName, zipBuf, expectedSubstr) {
      try {
        await runWorkerTask({ mode: "zip", rootName: "test", zipBuffer: zipBuf }, [zipBuf]);
        results.push({ name: testName, pass: false, detail: "拒否されず通過してしまいました" });
      } catch (err) {
        const matched = !expectedSubstr || err.message.includes(expectedSubstr);
        results.push({ name: testName, pass: matched, detail: err.message });
      }
    }

    try {
      // テスト1: Central Directory の宣言サイズが EOCD 境界を超える不正ZIPの拒否
      const badCdZip = buildCustomTestZip([{ name: "a.py", data: "x=1" }], { corruptCdSize: 99999 });
      await expectReject("1. Central Directory 境界逸脱(EOCD侵食)の拒否", badCdZip, "Central Directory");

      // テスト2: ローカルヘッダとCentral Directoryのファイル名不整合の拒否
      const mismatchZip = buildCustomTestZip([{ name: "safe.py", lfhName: "evil.py", data: "x=1" }]);
      await expectReject("2. ローカルヘッダとCentral Directoryの不整合拒否", mismatchZip, "矛盾");

      // テスト3: エントリ領域オーバーラップ(重複参照)ZIPの拒否
      const overlapZip = buildCustomTestZip([
        { name: "a.py", data: "print(1)" },
        { name: "b.py", data: "print(1)", forceLhOffset: 0, skipLocalHeaderWrite: true }
      ]);
      await expectReject("3. エントリ領域重複(Overlap)アーカイブの拒否", overlapZip, "Overlap");

      // テスト4: CRC-32 不一致（データ破損・改ざん）の拒否
      const badCrcZip = buildCustomTestZip([{ name: "corrupt.py", data: "print('hello')", customCrc: 0x12345678 }]);
      await expectReject("4. CRC-32 不一致（改ざんデータ）の検証と拒否", badCrcZip, "CRC_MISMATCH");

      // テスト5: ヘッダサイズ偽装型 Deflate Zip Bomb の実展開ストリーム遮断
      // 20KBのデータをDeflate圧縮し、ヘッダ上のuncompSizeを「64バイト」に偽装して単体上限10KBのWorkerへ投入
      const bombPayload = new Uint8Array(20 * 1024).fill(65);
      const compressedBomb = await deflateRawBytes(bombPayload);
      const mainSuitZip = buildCustomTestZip([
        {
          name: "src/spoofed_bomb.py",
          data: bombPayload,
          compressedData: compressedBomb,
          method: 8,
          fakeUncompSize: 64 // ヘッダサイズを小さく偽装
        },
        { name: "../../etc/passwd.py", data: "print('zip_slip')" },
        { name: ".env.local", data: "SECRET=1" },
        {
          name: "src/unquoted_secrets.py",
          data: "password = my-secret-value\nAPI_KEY=example-secret-value\n# Authorization: Bearer example-token\n"
        },
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
            customLimits: { MAX_SINGLE_FILE_BYTES: 10 * 1024 } // 単体上限 10KB で実ストリーム遮断を試験
          }
        },
        [mainSuitZip]
      );

      const md = suitRes.markdown;
      results.push({
        name: "5. ヘッダ偽装Deflate Zip Bombの実ストリーム遮断",
        pass: !md.includes("spoofed_bomb.py") && suitRes.stats.warnings.some((w) => w.includes("Zip Bomb防御")),
        detail: "DecompressionStreamチャンク監視により10KB超過時点で遮断"
      });

      results.push({
        name: "6. Zip Slip (../../) パストラバーサル遮断",
        pass: !md.includes("zip_slip") && !md.includes("passwd"),
        detail: "不正相対パスを拒否"
      });

      results.push({
        name: "7. 引用符なし秘密情報(password = ..., API_KEY=..., Bearer)の検出・マスク",
        pass:
          !md.includes("my-secret-value") &&
          !md.includes("example-secret-value") &&
          !md.includes("example-token") &&
          suitRes.stats.redactedSecretsCount >= 3,
        detail: `${suitRes.stats.redactedSecretsCount}箇所の非引用符クレデンシャル・Bearerを捕捉`
      });

      results.push({
        name: "8. 機密ファイル名 (.env.local) の除外",
        pass: !md.includes("SECRET=1") && suitRes.stats.secretFilesBlocked >= 1,
        detail: "ブラックリストにより除外"
      });

      results.push({
        name: "9. __proto__ / constructor 特殊名のMap/Set安全ツリー構築",
        pass: md.includes("📁 __proto__/") && md.includes("📄 constructor.py"),
        detail: "プロトタイプ汚染なしでツリー出力"
      });

      results.push({
        name: "10. バッククォートを含むファイル名のCommonMarkコードスパン保護",
        pass: md.includes("```src/back`tick``name.py```"),
        detail: "3連バッククォートデリミタでヘッダ破壊を防止"
      });

      results.push({
        name: "11. 本文内3連バッククォートに対する動的4連フェンス生成",
        pass: md.includes("````md"),
        detail: "コードブロック閉じ破壊を防止"
      });

      // テスト12: 総展開バジェット上限到達時の停止 ＆ キャンセル時のPromise即時reject解決検証
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

      // キャンセルによるPromise即時reject検証
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
        name: "12. 総展開バジェット上限停止 ＆ キャンセル時のPromise確実決済",
        pass: budgetPassed && cancelSettled,
        detail: `バジェット停止(2/3件で停止=${budgetPassed}), キャンセルPromise即時reject=${cancelSettled}`
      });

      let allPassed = true;
      for (const r of results) {
        appendLog(`  ${r.pass ? "✅ PASS" : "❌ FAIL"} : ${r.name} (${r.detail})`);
        if (!r.pass) allPassed = false;
      }

      setUIIdleState(false);
      appendLog(
        allPassed
          ? "=== 🎉 全12項目の厳格セキュリティ検証にすべて合格しました ==="
          : "=== ⚠️ 一部の検証項目が失敗しました ==="
      );
    } catch (err) {
      setUIIdleState(false);
      appendLog(`❌ 自己診断中に予期しない例外: ${err.message}`);
    }
  });

  appendLog("🛡️ Strict Audited Edition 初期化完了 (Strict CSP / CRC-32検証 / 出力前監査プレビュー有効)");
})();
