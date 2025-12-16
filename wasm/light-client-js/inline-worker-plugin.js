import { build } from "esbuild";
import findCacheDir from "find-cache-dir";
import fs from "fs";
import path from "path";


export default function inlineWorkerPlugin(
    workerPluginConfig = {},
) {
    return {
        name: "esbuild-plugin-inline-worker",

        setup(build) {
            build.onLoad(
                { filter: /\.worker.(js|jsx|ts|tsx)$/ },
                async ({ path: workerPath }) => {
                    // const workerCode = await fs.promises.readFile(workerPath, {
                    //   encoding: 'utf-8',
                    // });

                    const workerCode = await buildWorker(workerPath, workerPluginConfig);
                    return {
                        contents: `import inlineWorker from '__inline-worker'
export default function Worker() {
  return inlineWorker(${JSON.stringify(workerCode)});
}
`,
                        loader: "js",
                    };
                },
            );

            const options = {
                name: workerPluginConfig.workerName || undefined,
                ...workerPluginConfig.workerArguments,
            }

            const inlineWorkerFunctionCode = `
export default function inlineWorker(scriptText) {
  // 检测是否在 Node.js 环境
  if (typeof process !== 'undefined' && process.versions && process.versions.node) {
    const { Worker } = require('worker_threads');
    const fs = require('fs');
    const path = require('path');
    const os = require('os');
    const crypto = require('crypto');
    
    // 生成临时文件路径
    const hash = crypto.createHash('md5').update(scriptText).digest('hex').slice(0, 8);
    const tempDir = os.tmpdir();
    const tempFilePath = path.join(tempDir, \`worker-\${hash}-\${Date.now()}.mjs\`);
    
    // 写入临时文件
    fs.writeFileSync(tempFilePath, scriptText, 'utf-8');
    console.log('[inline-worker] Created temporary worker file:', tempFilePath);
    
    // 使用文件路径创建 Worker
    const worker = new Worker(tempFilePath, ${JSON.stringify(options)});
    
    // 清理临时文件（在 worker 终止或错误时）
    const cleanup = () => {
      try {
        if (fs.existsSync(tempFilePath)) {
        //   fs.unlinkSync(tempFilePath);
        //   console.log('[inline-worker] Cleaned up temporary worker file:', tempFilePath);
        }
      } catch (err) {
        console.error('[inline-worker] Failed to cleanup temporary file:', err);
      }
    };
    
    worker.on('exit', cleanup);
    // worker.on('error', cleanup);
    worker.on('error', (err) => {
      console.error('[inline-worker] Worker error:', err);
      cleanup();
    });
    
    return worker;
  } else {
    // 浏览器环境
    const blob = new Blob([scriptText], {type: 'text/javascript'});
    const url = URL.createObjectURL(blob);
    const worker = new Worker(url, ${JSON.stringify(options)});
    URL.revokeObjectURL(url);
    return worker;
  }
}
`;

            build.onResolve({ filter: /^__inline-worker$/ }, ({ path }) => {
                return { path, namespace: "inline-worker" };
            });
            build.onLoad({ filter: /.*/, namespace: "inline-worker" }, () => {
                return { contents: inlineWorkerFunctionCode, loader: "js" };
            });
        },
    };
}

const cacheDir = findCacheDir({
    name: "esbuild-plugin-inline-worker",
    create: true,
});

async function buildWorker(workerPath, pluginConfig) {
    const scriptNameParts = path.basename(workerPath).split(".");
    scriptNameParts.pop();
    scriptNameParts.push("js");
    const scriptName = scriptNameParts.join(".");
    if (!cacheDir) {
        throw new Error("Cache directory not found. Please ensure 'find-cache-dir' is installed.");
    }
    const bundlePath = path.resolve(cacheDir, scriptName);

    if (pluginConfig.buildOptions) {
        delete pluginConfig.buildOptions.entryPoints;
        delete pluginConfig.buildOptions.outfile;
        delete pluginConfig.buildOptions.outdir;
    }

    await build({
        entryPoints: [workerPath],
        bundle: true,
        minify: true,
        outfile: bundlePath,
        target: "esnext",
        format: "esm",
        platform: "node",
        ...pluginConfig.buildOptions,
    });

    return fs.promises.readFile(bundlePath, { encoding: "utf-8" });
}
