import React, { useState } from 'react';
import type { AnalysisResponse } from '../api';
import { ProvenanceBadge } from './ProvenanceBadge';
import { ChevronDown, ChevronRight, FileSearch, Link } from 'lucide-react';

interface Props {
  analysis: AnalysisResponse;
}

export const EvidenceTab: React.FC<Props> = ({ analysis }) => {
  const [expandedRow, setExpandedRow] = useState<string | null>(null);

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      
      {/* Evidence Table */}
      <div>
         <div className="flex items-center gap-3 mb-4">
           <FileSearch className="w-5 h-5 text-gray-400" />
           <h3 className="mono-label text-gray-300 m-0">Forensic Evidence Ledger</h3>
         </div>
         
         <div className="bg-surface border border-hairline rounded overflow-hidden">
           <table className="w-full text-left border-collapse">
             <thead>
               <tr className="bg-base border-b border-hairline">
                 <th className="py-3 px-4 font-mono text-[10px] uppercase text-gray-500 w-8"></th>
                 <th className="py-3 px-4 font-mono text-[10px] uppercase text-gray-500">ID</th>
                 <th className="py-3 px-4 font-mono text-[10px] uppercase text-gray-500">Type</th>
                 <th className="py-3 px-4 font-mono text-[10px] uppercase text-gray-500">Source</th>
                 <th className="py-3 px-4 font-mono text-[10px] uppercase text-gray-500">Confidence</th>
                 <th className="py-3 px-4 font-mono text-[10px] uppercase text-gray-500 text-right">Provenance</th>
               </tr>
             </thead>
             <tbody className="divide-y divide-hairline">
               {analysis.evidence.length === 0 && (
                 <tr><td colSpan={6} className="py-8 text-center font-mono text-sm text-gray-500 italic">No forensic evidence found.</td></tr>
               )}
               {analysis.evidence.map((ev) => (
                 <React.Fragment key={ev.id}>
                   <tr 
                     className="hover:bg-base/50 cursor-pointer transition-colors"
                     onClick={() => setExpandedRow(expandedRow === ev.id ? null : ev.id)}
                   >
                     <td className="py-3 px-4 text-gray-500">
                       {expandedRow === ev.id ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                     </td>
                     <td className="py-3 px-4 font-mono text-xs text-gray-300">{ev.id}</td>
                     <td className="py-3 px-4 font-mono text-xs text-accent uppercase">{ev.type}</td>
                     <td className="py-3 px-4 font-mono text-xs text-gray-400">{ev.source}</td>
                     <td className="py-3 px-4 font-mono text-xs text-white">{(ev.confidence * 100).toFixed(1)}%</td>
                     <td className="py-3 px-4 text-right">
                       <ProvenanceBadge provenance={ev.provenance} />
                     </td>
                   </tr>
                   {expandedRow === ev.id && (
                     <tr className="bg-base">
                       <td colSpan={6} className="p-0 border-t border-hairline border-dashed">
                         <div className="p-6 pl-14 grid grid-cols-1 md:grid-cols-2 gap-8">
                           <div>
                             <div className="mono-label text-gray-500 mb-2">Description / Indicator</div>
                             <div className="text-sm text-gray-300 font-mono bg-surface p-3 border border-hairline rounded">
                               {ev.description}
                             </div>
                           </div>
                           <div>
                             <div className="mono-label text-gray-500 mb-2">Related Correlations</div>
                             <div className="space-y-2">
                               {analysis.correlation.filter(c => c.evidence_ids.includes(ev.id)).length > 0 ? (
                                 analysis.correlation.filter(c => c.evidence_ids.includes(ev.id)).map((corr, idx) => (
                                   <div key={idx} className="flex items-start gap-2 text-xs text-gray-400">
                                     <Link className="w-3 h-3 text-accent mt-0.5 shrink-0" />
                                     <span><strong className="text-gray-300">{corr.rule}:</strong> {corr.rationale}</span>
                                   </div>
                                 ))
                               ) : (
                                 <div className="text-xs text-gray-600 font-mono">No direct correlation rules match.</div>
                               )}
                             </div>
                           </div>
                         </div>
                       </td>
                     </tr>
                   )}
                 </React.Fragment>
               ))}
             </tbody>
           </table>
         </div>
      </div>
      
      {/* Correlation Rules */}
      <div>
         <div className="flex items-center gap-3 mb-4">
           <Link className="w-5 h-5 text-gray-400" />
           <h3 className="mono-label text-gray-300 m-0">Event Correlation Graph</h3>
         </div>
         
         <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
           {analysis.correlation.length === 0 ? (
             <div className="col-span-full text-gray-500 font-mono italic p-4 text-center border border-hairline rounded bg-surface">No correlations established.</div>
           ) : (
             analysis.correlation.map((corr, i) => (
               <div key={i} className="p-5 bg-surface rounded border border-hairline relative">
                 <div className="flex justify-between items-start mb-3">
                   <h4 className="font-mono text-sm font-bold text-white uppercase">{corr.rule}</h4>
                   <ProvenanceBadge provenance={corr.provenance} />
                 </div>
                 <p className="text-sm text-gray-400 mb-4 leading-relaxed">{corr.rationale}</p>
                 <div className="flex flex-wrap gap-2">
                   {corr.evidence_ids.map(id => (
                     <span key={id} className="text-[10px] font-mono border border-hairline bg-base text-gray-400 px-2 py-1 rounded">{id}</span>
                   ))}
                 </div>
               </div>
             ))
           )}
         </div>
      </div>
    </div>
  );
};
