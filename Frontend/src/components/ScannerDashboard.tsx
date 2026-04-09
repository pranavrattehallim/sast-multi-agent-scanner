import React from "react";
import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Upload, FileArchive, ShieldCheck, Download, Loader2, CheckCircle2, AlertCircle, FolderTree, Clock3 } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

type ScanStatus = "idle" | "uploading" | "queued" | "scanning" | "completed" | "failed";
type JobResponse = { job_id: string; status: ScanStatus; filename?: string; };
type StatusResponse = { job_id: string; status: ScanStatus; progress: number; stage: string; filename?: string; files_scanned?: number; total_files?: number; report_ready?: boolean; error?: string | null; };

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

function statusTone(status: ScanStatus) {
  switch (status) {
    case "completed": return "bg-green-100 text-green-700 border-green-200";
    case "failed": return "bg-red-100 text-red-700 border-red-200";
    case "scanning": return "bg-amber-100 text-amber-700 border-amber-200";
    case "queued": case "uploading": return "bg-blue-100 text-blue-700 border-blue-200";
    default: return "bg-slate-100 text-slate-700 border-slate-200";
  }
}

export default function ScannerDashboard() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [model, setModel] = useState("deepseek-coder-v2:latest");
  const [status, setStatus] = useState<ScanStatus>("idle");
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState("Waiting for upload");
  const [jobId, setJobId] = useState<string | null>(null);
  const [filesScanned, setFilesScanned] = useState(0);
  const [totalFiles, setTotalFiles] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [reportReady, setReportReady] = useState(false);

  const canSubmit = useMemo(() => !!selectedFile && status !== "uploading" && status !== "queued" && status !== "scanning", [selectedFile, status]);

  useEffect(() => {
    if (!jobId || (status !== "queued" && status !== "scanning")) return;
    const timer = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/api/scans/${jobId}/status`);
        if (!res.ok) throw new Error("Unable to fetch scan status");
        const data: StatusResponse = await res.json();
        setStatus(data.status);
        setProgress(data.progress ?? 0);
        setStage(data.stage ?? "Scanning");
        setFilesScanned(data.files_scanned ?? 0);
        setTotalFiles(data.total_files ?? 0);
        setReportReady(!!data.report_ready);
        setError(data.error ?? null);
        if (data.status === "completed" || data.status === "failed") clearInterval(timer);
      } catch (err) {
        clearInterval(timer);
        setStatus("failed");
        setError(err instanceof Error ? err.message : "Unknown polling error");
      }
    }, 2000);
    return () => clearInterval(timer);
  }, [jobId, status]);

  async function handleUploadAndScan() {
    if (!selectedFile) return;
    setError(null); setReportReady(false); setStatus("uploading");
    setStage("Uploading archive"); setProgress(10); setFilesScanned(0); setTotalFiles(0);
    try {
      const formData = new FormData();
      formData.append("file", selectedFile);
      formData.append("model", model);
      const res = await fetch(`${API_BASE}/api/scans`, { method: "POST", body: formData });
      if (!res.ok) throw new Error("Upload failed");
      const data: JobResponse = await res.json();
      setJobId(data.job_id);
      setStatus(data.status || "queued");
      setStage("Queued for scanning");
      setProgress(20);
    } catch (err) {
      setStatus("failed");
      setError(err instanceof Error ? err.message : "Unknown upload error");
      setStage("Upload failed");
      setProgress(0);
    }
  }

  function handleDownload() {
    if (!jobId) return;
    window.open(`${API_BASE}/api/scans/${jobId}/report`, "_blank");
  }

  return (
    <div className="min-h-screen bg-slate-50 p-6 md:p-10">
      <div className="mx-auto grid max-w-7xl gap-6 lg:grid-cols-3">
        <motion.div initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} className="lg:col-span-2">
          <Card className="rounded-3xl border-0 shadow-xl">
            <CardHeader className="space-y-3 pb-2">
              <div className="flex items-center gap-3">
                <div className="rounded-2xl bg-slate-900 p-3 text-white"><ShieldCheck className="h-6 w-6" /></div>
                <div>
                  <CardTitle className="text-3xl font-semibold tracking-tight">ScannerAI Dashboard</CardTitle>
                  <CardDescription className="text-base">Upload a project archive, trigger the agent pipeline, and download the final report from the same page.</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="grid gap-6 pt-6">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="rounded-3xl border border-dashed border-slate-300 bg-white p-5">
                  <Label htmlFor="projectZip" className="mb-3 block text-sm font-medium text-slate-700">Project archive</Label>
                  <label htmlFor="projectZip" className="flex min-h-48 cursor-pointer flex-col items-center justify-center rounded-2xl border border-slate-200 bg-slate-50 p-6 text-center hover:bg-slate-100">
                    <Upload className="mb-3 h-8 w-8 text-slate-600" />
                    <div className="text-base font-medium text-slate-900">Drop ZIP/TAR archive here or click to browse</div>
                    <div className="mt-2 text-sm text-slate-500">Recommended: zipped source folder with exclusions already applied</div>
                    {selectedFile && (
                      <div className="mt-4 inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm text-slate-700">
                        <FileArchive className="h-4 w-4" />{selectedFile.name}
                      </div>
                    )}
                  </label>
                  <Input id="projectZip" type="file" accept=".zip,.tar,.gz,.tgz" className="hidden" onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSelectedFile(e.target.files?.[0] ?? null)} />
                </div>
                <div className="rounded-3xl border border-slate-200 bg-white p-5">
                  <Label htmlFor="model" className="mb-3 block text-sm font-medium text-slate-700">Model</Label>
                  <Input id="model" value={model} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setModel(e.target.value)} placeholder="deepseek-coder-v2:latest" className="mb-6" />
                  <div className="grid gap-3">
                    <Button className="h-12 rounded-2xl text-base" onClick={handleUploadAndScan} disabled={!canSubmit}>
                      {status === "uploading" || status === "queued" || status === "scanning"
                        ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Processing</>
                        : <><ShieldCheck className="mr-2 h-4 w-4" /> Start Scan</>}
                    </Button>
                    <Button variant="outline" className="h-12 rounded-2xl text-base" onClick={handleDownload} disabled={!reportReady || !jobId}>
                      <Download className="mr-2 h-4 w-4" /> Download Report
                    </Button>
                  </div>
                </div>
              </div>
              <div className="rounded-3xl border border-slate-200 bg-white p-5">
                <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div className="text-lg font-semibold text-slate-900">Pipeline status</div>
                    <div className="text-sm text-slate-500">Upload → extract → scan → generate report</div>
                  </div>
                  <Badge className={`rounded-full border px-4 py-1 text-sm ${statusTone(status)}`}>{status.toUpperCase()}</Badge>
                </div>
                <Progress value={progress} className="h-3" />
                <div className="mt-4 grid gap-3 md:grid-cols-3">
                  <div className="rounded-2xl bg-slate-50 p-4">
                    <div className="mb-2 flex items-center gap-2 text-sm text-slate-500"><Clock3 className="h-4 w-4" /> Current stage</div>
                    <div className="font-medium text-slate-900">{stage}</div>
                  </div>
                  <div className="rounded-2xl bg-slate-50 p-4">
                    <div className="mb-2 flex items-center gap-2 text-sm text-slate-500"><FolderTree className="h-4 w-4" /> Files scanned</div>
                    <div className="font-medium text-slate-900">{filesScanned} / {totalFiles}</div>
                  </div>
                  <div className="rounded-2xl bg-slate-50 p-4">
                    <div className="mb-2 flex items-center gap-2 text-sm text-slate-500"><FileArchive className="h-4 w-4" /> Job ID</div>
                    <div className="truncate font-medium text-slate-900">{jobId ?? "Not started"}</div>
                  </div>
                </div>
                {status === "completed" && (
                  <div className="mt-4 flex items-center gap-2 rounded-2xl border border-green-200 bg-green-50 p-4 text-green-700">
                    <CheckCircle2 className="h-5 w-5" /> Scan finished. Report is ready to download.
                  </div>
                )}
                {status === "failed" && (
                  <div className="mt-4 flex items-center gap-2 rounded-2xl border border-red-200 bg-red-50 p-4 text-red-700">
                    <AlertCircle className="h-5 w-5" /> {error ?? "Scan failed"}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08 }}>
          <Card className="rounded-3xl border-0 shadow-xl">
            <CardHeader>
              <CardTitle className="text-xl">Execution flow</CardTitle>
              <CardDescription>Backend contract expected by this UI</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 text-sm text-slate-600">
              <div className="rounded-2xl bg-slate-50 p-4"><div className="font-semibold text-slate-900">POST /api/scans</div><div>Accept multipart upload and create a scan job.</div></div>
              <div className="rounded-2xl bg-slate-50 p-4"><div className="font-semibold text-slate-900">GET /api/scans/:jobId/status</div><div>Return status, stage, progress, file counts, and report readiness.</div></div>
              <div className="rounded-2xl bg-slate-50 p-4"><div className="font-semibold text-slate-900">GET /api/scans/:jobId/report</div><div>Return the generated markdown or PDF report for download.</div></div>
              <div className="rounded-2xl bg-slate-50 p-4">
                <div className="font-semibold text-slate-900">Storage layout</div>
                <div className="mt-2 font-mono text-xs text-slate-700">
                  uploads/&lt;jobId&gt;/source.zip<br />workspace/&lt;jobId&gt;/extracted/<br />reports/&lt;jobId&gt;/report.md<br />jobs.db
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </div>
  );
}
