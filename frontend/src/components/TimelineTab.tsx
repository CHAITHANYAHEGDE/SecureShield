import React from 'react';
import type { AnalysisResponse } from '../api';

interface Props {
  analysis: AnalysisResponse;
  scrubberValue?: number;
}

export const TimelineTab: React.FC<Props> = ({ analysis, scrubberValue = 100 }) => {
  const visibleCount = analysis.timeline.length === 0 ? 0 : Math.max(1, Math.ceil(analysis.timeline.length * (scrubberValue / 100)));
  const visibleTimeline = analysis.timeline.slice(0, visibleCount);

  return (
    <div className="space-y-6">
      <div className="bg-surface border border-hairline p-5 rounded relative">
         {/* Vertical line connecting events */}
         <div className="absolute top-10 left-12 bottom-10 w-0.5 bg-hairline"></div>
         
         <div className="space-y-8 relative z-10">
           {visibleTimeline.length === 0 ? (
             <div className="text-gray-500 font-mono italic p-4 text-center">No timeline events reconstructed.</div>
           ) : (
             visibleTimeline.map((event, i) => (
               <div key={i} className="flex items-start">
                 {/* Step circle */}
                 <div className="w-8 h-8 rounded-full bg-base border-2 border-accent flex items-center justify-center text-xs font-bold text-accent z-10 mt-1 shrink-0">
                   {event.order}
                 </div>
                 
                 <div className="ml-6 flex-1 bg-base/80 p-4 rounded border border-hairline relative">
                   {/* Left pointing arrow */}
                   <div className="absolute top-4 -left-2 w-4 h-4 bg-base/80 border-l border-t border-hairline transform -rotate-45"></div>
                   
                   <div className="flex justify-between items-start mb-2">
                     <span className="text-[10px] font-mono bg-hairline text-gray-300 px-2 py-0.5 rounded">{event.evidence_ids.join(', ')}</span>
                   </div>
                   
                   <h4 className="text-sm font-bold text-white mb-2">{event.stage}</h4>
                   <p className="text-sm text-gray-300 mb-3">{event.description}</p>
                   
                   {(event as any).synthetic_note && (
                     <div className="text-xs text-amber-500/80 font-mono mt-2 pt-2 border-t border-hairline/50 flex items-start">
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
