import React from 'react';
import type { AnalysisResponse } from '../api';
import { GitCommit, Layers } from 'lucide-react';

interface Props {
  analysis: AnalysisResponse;
  scrubberValue?: number;
}

export const TimelineTab: React.FC<Props> = ({ analysis, scrubberValue = 100 }) => {
  const visibleCount = analysis.timeline.length === 0 ? 0 : Math.max(1, Math.ceil(analysis.timeline.length * (scrubberValue / 100)));
  const visibleTimeline = analysis.timeline.slice(0, visibleCount);

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <div className="flex items-center gap-3 mb-6">
        <Layers className="w-5 h-5 text-gray-400" />
        <h3 className="mono-label text-gray-300 m-0">Logical Attack Sequence</h3>
      </div>

      <div className="bg-surface border border-hairline p-8 rounded relative">
         {/* Vertical line connecting events */}
         <div className="absolute top-12 left-[3.25rem] bottom-12 w-px bg-hairline"></div>
         
         <div className="space-y-12 relative z-10">
           {visibleTimeline.length === 0 ? (
             <div className="text-gray-500 font-mono italic p-4 text-center">No timeline events reconstructed.</div>
           ) : (
             visibleTimeline.map((event, i) => (
               <div key={i} className="flex items-start group">
                 {/* Step circle */}
                 <div className="w-10 h-10 rounded-full bg-base border border-hairline flex items-center justify-center text-xs font-mono text-gray-400 z-10 mt-1 shrink-0 group-hover:border-accent group-hover:text-accent transition-colors">
                   S{event.order}
                 </div>
                 
                 <div className="ml-8 flex-1">
                   <div className="flex items-center gap-3 mb-2">
                     <h4 className="text-base font-display text-white uppercase tracking-wide group-hover:text-accent transition-colors">{event.stage}</h4>
                     <span className="text-[10px] font-mono border border-hairline bg-base text-gray-500 px-2 py-0.5 rounded uppercase tracking-wider shadow-sm">
                       {event.provenance}
                     </span>
                   </div>
                   
                   <p className="text-sm text-gray-400 mb-4 leading-relaxed max-w-3xl">{event.description}</p>
                   
                   {event.evidence_ids.length > 0 && (
                     <div className="flex items-center gap-2">
                       <GitCommit className="w-3 h-3 text-gray-600" />
                       <span className="text-xs font-mono text-gray-500">Related Evidence:</span>
                       <div className="flex gap-2">
                         {event.evidence_ids.map(id => (
                           <span key={id} className="text-[10px] font-mono bg-base border border-hairline text-gray-400 px-1.5 py-0.5 rounded">{id}</span>
                         ))}
                       </div>
                     </div>
                   )}
                   
                   {(event as any).synthetic_note && (
                     <div className="text-[10px] text-amber-500/80 font-mono mt-3 uppercase tracking-wide flex items-center">
                        <span className="mr-2">⚠</span>
                        <span>{(event as any).synthetic_note}</span>
                     </div>
                   )}
                 </div>
               </div>
             ))
           )}
         </div>
      </div>
    </div>
  );
};
