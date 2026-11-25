import { ChevronLeft, ChevronRight } from "lucide-react";

export function PaginationBar({
  total,
  limit,
  offset,
  onPageChange,
  onLimitChange,
}: {
  total: number;
  limit: number;
  offset: number;
  onPageChange: (nextOffset: number) => void;
  onLimitChange?: (nextLimit: number) => void;
}) {
  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const start = total === 0 ? 0 : offset + 1;
  const end = Math.min(total, offset + limit);

  return (
    <div className="mt-4 flex flex-col items-center justify-between gap-3 border-t border-slate-800/80 pt-4 text-xs text-slate-400 sm:flex-row">
      <div className="tabular-nums">
        Showing <span className="font-medium text-slate-200">{start}</span>–
        <span className="font-medium text-slate-200">{end}</span> of{" "}
        <span className="font-medium text-slate-200">{total}</span> items
      </div>

      <div className="flex items-center gap-3">
        {onLimitChange && (
          <label className="flex items-center gap-1.5">
            <span>Rows</span>
            <select
              aria-label="Page size"
              value={limit}
              onChange={(e) => onLimitChange(Number(e.target.value))}
              className="rounded border border-slate-700 bg-[#111620] px-2 py-1 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
            >
              {[10, 25, 50, 100].map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </label>
        )}

        <div className="flex items-center gap-1.5">
          <button
            type="button"
            aria-label="Previous page"
            disabled={offset === 0}
            onClick={() => onPageChange(Math.max(0, offset - limit))}
            className="inline-flex items-center gap-1 rounded border border-slate-700 bg-[#111620] px-2.5 py-1 text-slate-200 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ChevronLeft className="h-3.5 w-3.5" />
            Prev
          </button>
          <span className="px-2 tabular-nums text-slate-300">
            Page {currentPage} / {totalPages}
          </span>
          <button
            type="button"
            aria-label="Next page"
            disabled={offset + limit >= total}
            onClick={() => onPageChange(offset + limit)}
            className="inline-flex items-center gap-1 rounded border border-slate-700 bg-[#111620] px-2.5 py-1 text-slate-200 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Next
            <ChevronRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}
