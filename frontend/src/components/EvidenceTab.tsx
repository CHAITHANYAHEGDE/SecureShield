import React from 'react';
import type { AnalysisResponse } from '../api';
import { ProvenanceBadge } from './ProvenanceBadge';

interface Props {
  analysis: AnalysisResponse;
}

export const EvidenceTab: React.FC<Props> = ({ analysis }) => {
  return (
    <div className="space-y-6">
      <div className="bg-surface border border-hairline p-5 rounded">
         <h3 className="mono-label text-gray-400 mb-4 border-b border-hairline pb-2">Extracted Forensic Evidence</h3>
         
         {analysis.evidence.length === 0 ? (
           <div className="text-gray-500 font-mono italic p-4 text-center">No evidence extracted.</div>
         ) : (
           <div className="space-y-4">
             {analysis.evidence.map((ev, i) => (
               <div key={i} className="flex justify-between items-start p-4 bg-base/50 rounded border border-hairline">
                 <div className="flex-1">
                   <div className="flex items-center space-x-3 mb-2">
                     <span className="text-xs font-mono bg-hairline text-gray-300 px-2 py-1 rounded">{ev.id}</span>
                     <span className="text-xs font-mono text-accent uppercase tracking-wider">{ev.type}</span>
                     <span className="text-xs font-mono text-gray-500">Source: {ev.source}</span>
                   </div>
                   <div className="text-sm text-gray-300 leading-relaxed mb-2">
                     {ev.description}
                   </div>
                   <div className="text-xs font-mono text-gray-500">
                     Confidence: {(ev.confidence * 100).toFixed(1)}%
                   </div>
                 </div>
                 <div className="ml-4">
                   <ProvenanceBadge provenance={ev.provenance} />
                 </div>
               </div>
             ))}
           </div>
         )}
      </div>
      
      <div className="bg-surface border border-hairline p-5 rounded">
         <h3 className="mono-label text-gray-400 mb-4 border-b border-hairline pb-2">Evidence Correlation Rules</h3>
         
         {analysis.correlation.length === 0 ? (
           <div className="text-gray-500 font-mono italic p-4 text-center">No correlations established.</div>
         ) : (
           <div className="space-y-4">
             {analysis.correlation.map((corr, i) => (
               <div key={i} className="p-4 bg-base/50 rounded border border-hairline">
                 <div className="flex justify-between items-start mb-2">
                   <h4 className="text-sm font-bold text-white">{corr.rule}</h4>
                   <ProvenanceBadge provenance={corr.provenance} />
                 </div>
                 <p className="text-sm text-gray-400 mb-3">{corr.rationale}</p>
                 <div className="flex flex-wrap gap-2">
                   {corr.evidence_ids.map(id => (
                     <span key={id} className="text-xs font-mono bg-hairline text-gray-400 px-2 py-1 rounded">{id}</span>
                   ))}
                 </div>
               </div>
             ))}
           </div>
         )}
      </div>
    </div>
  );
};
