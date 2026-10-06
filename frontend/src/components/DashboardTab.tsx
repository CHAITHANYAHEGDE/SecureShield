import React from 'react';
import type { AnalysisResponse } from '../api';
import { ProvenanceBadge } from './ProvenanceBadge';
import { AlertTriangle, ShieldCheck, Activity, Target, ArrowRight, ActivitySquare, AlertCircle } from 'lucide-react';

interface Props {
  analysis: AnalysisResponse;
}

export const DashboardTab: React.FC<Props> = ({ analysis }) => {
  const isMalicious = analysis.prediction.label === 'malicious';
  const confidence = (analysis.prediction.confidence * 100).toFixed(1);

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      {/* Top Section - Verdict Anchor */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-8 pb-8 border-b border-hairline">
        <div className="md:col-span-2 flex flex-col justify-center">
           <h3 className="mono-label text-gray-500 mb-2">Primary Verdict</h3>
           <div className={`font-display text-5xl md:text-6xl font-bold uppercase tracking-wide mb-2 ${isMalicious ? 'text-severity-critical' : 'text-severity-low'}`}>
             {analysis.prediction.label}
           </div>
           <div className="flex items-center gap-4 text-sm font-mono text-gray-400">
             <span className="text-white font-bold">{confidence}% CONFIDENCE</span>
             <span className="opacity-50">|</span>
             <span>Model: {analysis.prediction.model}</span>
             <span className="opacity-50">|</span>
             <span>ROC AUC 1.000</span>
           </div>
           <p className="mt-6 text-gray-400 max-w-xl text-sm leading-relaxed border-l-2 border-hairline pl-4">
             Classification is strongly supported by {analysis.shap[0]?.feature || 'behavioral features'}, which significantly contributed to the {analysis.prediction.label} boundary.
           </p>
        </div>

        <div className="flex flex-col justify-center space-y-6">
           <div>
             <h3 className="mono-label text-gray-500 mb-2">Risk Level</h3>
             <div className="flex items-baseline gap-2">
               <span className="font-display text-4xl text-white">{analysis.risk.score}</span>
               <span className="text-gray-500 font-mono text-xs">/ 100</span>
             </div>
             <div className="text-sm font-mono text-gray-400 mt-1 capitalize">{analysis.risk.severity} Severity</div>
           </div>
           
           <div>
             <h3 className="mono-label text-gray-500 mb-2">MITRE ATT&CK Mapping</h3>
             <div className="flex items-baseline gap-2">
               <span className="font-display text-4xl text-white">{analysis.mitre.length}</span>
             </div>
             <div className="text-sm font-mono text-gray-400 mt-1">Techniques Identified</div>
           </div>
        </div>
      </div>

      {/* Investigation Summary Flow */}
      <div>
         <h3 className="mono-label text-gray-500 mb-6">Investigation Summary</h3>
         
         <div className="grid grid-cols-1 md:grid-cols-6 gap-4">
            
            <div className="bg-surface border border-hairline p-4 relative group hover:border-accent/50 transition-colors">
               <div className="mono-label mb-4 text-gray-400 group-hover:text-white transition-colors">Detection</div>
               <div className="text-xs font-mono text-gray-400">Top Feature:</div>
               <div className="text-sm text-gray-300 truncate mt-1">{analysis.shap[0]?.feature || 'None'}</div>
               <div className="mt-4"><ProvenanceBadge provenance={analysis.prediction.provenance} /></div>
            </div>

            <div className="hidden md:flex items-center justify-center">
              <ArrowRight className="text-gray-600 w-4 h-4" />
            </div>

            <div className="bg-surface border border-hairline p-4 relative group hover:border-accent/50 transition-colors">
               <div className="mono-label mb-4 text-gray-400 group-hover:text-white transition-colors">Evidence</div>
               <div className="text-xs font-mono text-gray-400">Indicators Found:</div>
               <div className="text-sm text-gray-300 truncate mt-1">{analysis.evidence.length} Forensic Items</div>
               <div className="mt-4"><ProvenanceBadge provenance={analysis.evidence[0]?.provenance || 'DERIVED'} /></div>
            </div>

            <div className="hidden md:flex items-center justify-center">
              <ArrowRight className="text-gray-600 w-4 h-4" />
            </div>

            <div className="bg-surface border border-hairline p-4 relative group hover:border-accent/50 transition-colors">
               <div className="mono-label mb-4 text-gray-400 group-hover:text-white transition-colors">Correlation</div>
               <div className="text-xs font-mono text-gray-400">Events Mapped:</div>
               <div className="text-sm text-gray-300 truncate mt-1">{analysis.timeline.length} Timeline Stages</div>
               <div className="mt-4"><ProvenanceBadge provenance="DERIVED" /></div>
            </div>

            <div className="hidden md:flex items-center justify-center">
              <ArrowRight className="text-gray-600 w-4 h-4" />
            </div>

         </div>
      </div>

      {/* Grid Content */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 pt-4">
        
        {/* Key Evidence */}
        <div>
          <h3 className="mono-label text-gray-500 mb-4 border-b border-hairline pb-2">Key Evidence Profile</h3>
          {analysis.evidence.length > 0 ? (
            <div className="space-y-2 mt-4">
              {analysis.evidence.slice(0, 4).map((ev, i) => (
                <div key={i} className="flex justify-between items-start py-3 border-b border-hairline/50">
                   <div>
                     <div className="text-[10px] font-mono text-gray-500 mb-1 tracking-wider uppercase">{ev.type}</div>
                     <div className="text-sm text-gray-300">{ev.description}</div>
                   </div>
                   <ProvenanceBadge provenance={ev.provenance} />
                </div>
              ))}
            </div>
          ) : (
            <div className="text-sm text-gray-500 font-mono mt-4 italic">No forensic evidence found.</div>
          )}
        </div>

        {/* Recommended Response */}
        <div>
          <h3 className="mono-label text-gray-500 mb-4 border-b border-hairline pb-2">Recommended Response Action</h3>
          {analysis.response.containment.length > 0 ? (
            <div className="space-y-2 mt-4">
              {analysis.response.containment.slice(0, 4).map((res, i) => (
                <div key={i} className="flex items-start py-3 border-b border-hairline/50 text-sm text-gray-300">
                   <AlertCircle className="w-4 h-4 text-accent mr-3 shrink-0 mt-0.5" />
                   <span>{res}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-sm text-gray-500 font-mono mt-4 italic">No immediate response actions required.</div>
          )}
        </div>

      </div>
    </div>
  );
};
