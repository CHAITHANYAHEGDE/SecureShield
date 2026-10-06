import React from 'react';
import type { AnalysisResponse } from '../api';
import { ProvenanceBadge } from './ProvenanceBadge';
import { AlertOctagon, CheckSquare } from 'lucide-react';

interface Props {
  analysis: AnalysisResponse;
}

export const RiskTab: React.FC<Props> = ({ analysis }) => {
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'text-red-500 bg-red-500/10 border-red-500/20';
      case 'HIGH': return 'text-amber-500 bg-amber-500/10 border-amber-500/20';
      case 'MEDIUM': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
      case 'LOW': return 'text-green-500 bg-green-500/10 border-green-500/20';
      default: return 'text-gray-400 bg-gray-500/10 border-gray-500/20';
    }
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-3 gap-6">
         {/* Risk Score Summary */}
         <div className="col-span-1 bg-surface border border-hairline p-6 rounded flex flex-col justify-center items-center text-center">
            <h3 className="mono-label text-gray-400 mb-6">Aggregated Risk Score</h3>
            
            <div className="relative mb-6">
               {/* Just a circular visual representation */}
               <svg className="w-32 h-32 transform -rotate-90">
                  <circle cx="64" cy="64" r="60" stroke="currentColor" strokeWidth="4" fill="transparent" className="text-base" />
                  <circle 
                    cx="64" 
                    cy="64" 
                    r="60" 
                    stroke="currentColor" 
                    strokeWidth="4" 
                    fill="transparent" 
                    strokeDasharray={377} 
                    strokeDashoffset={377 - (377 * analysis.risk.score) / 100} 
                    className={
                      analysis.risk.severity === 'CRITICAL' ? 'text-red-500' :
                      analysis.risk.severity === 'HIGH' ? 'text-amber-500' :
                      analysis.risk.severity === 'MEDIUM' ? 'text-yellow-500' : 'text-green-500'
                    }
                  />
               </svg>
               <div className="absolute inset-0 flex flex-col items-center justify-center">
                 <span className="text-3xl font-display font-bold text-white">{analysis.risk.score}</span>
               </div>
            </div>
            
            <div className={`px-4 py-1.5 rounded-full border font-bold text-sm tracking-wider uppercase ${getSeverityColor(analysis.risk.severity)}`}>
               {analysis.risk.severity} RISK
            </div>
            
            <div className="mt-6 flex justify-center">
               <ProvenanceBadge provenance={analysis.risk.provenance} />
            </div>
         </div>
         
         {/* Risk Factors */}
         <div className="col-span-2 bg-surface border border-hairline p-6 rounded">
            <h3 className="mono-label text-gray-400 mb-4 border-b border-hairline pb-2">Contributing Factors</h3>
            
            {(!analysis.risk.factors || analysis.risk.factors.length === 0) ? (
              <div className="text-gray-500 font-mono italic mt-8 text-center">No specific risk factors identified.</div>
            ) : (
              <ul className="space-y-4 mt-4">
                {analysis.risk.factors.map((factor, i) => (
                  <li key={i} className="flex items-start">
                    <AlertOctagon className="w-5 h-5 text-accent mr-3 shrink-0 mt-0.5" />
                    <span className="text-sm text-gray-300">{factor as unknown as string}</span>
                  </li>
                ))}
              </ul>
            )}
         </div>
      </div>
      
      {/* Response Plan */}
      <div className="bg-surface border border-hairline p-6 rounded">
         <h3 className="mono-label text-gray-400 mb-6 border-b border-hairline pb-2">Recommended Response Plan</h3>
         
         <div className="grid grid-cols-3 gap-6">
            <div className="space-y-3">
               <h4 className="font-mono text-sm font-bold text-amber-500 uppercase tracking-wide">Containment</h4>
               <ul className="space-y-2">
                 {analysis.response.containment && analysis.response.containment.length > 0 ? (
                   analysis.response.containment.map((action, i) => (
                     <li key={i} className="flex items-start text-sm text-gray-300 bg-base/50 p-2 rounded border border-hairline">
                       <CheckSquare className="w-4 h-4 text-gray-500 mr-2 shrink-0 mt-0.5" />
                       {action}
                     </li>
                   ))
                 ) : (
                   <li className="text-sm font-mono text-gray-500 italic">No containment actions.</li>
                 )}
               </ul>
            </div>
            
            <div className="space-y-3">
               <h4 className="font-mono text-sm font-bold text-blue-400 uppercase tracking-wide">Investigation</h4>
               <ul className="space-y-2">
                 {analysis.response.investigation && analysis.response.investigation.length > 0 ? (
                   analysis.response.investigation.map((action, i) => (
                     <li key={i} className="flex items-start text-sm text-gray-300 bg-base/50 p-2 rounded border border-hairline">
                       <CheckSquare className="w-4 h-4 text-gray-500 mr-2 shrink-0 mt-0.5" />
                       {action}
                     </li>
                   ))
                 ) : (
                   <li className="text-sm font-mono text-gray-500 italic">No investigation actions.</li>
                 )}
               </ul>
            </div>
            
            <div className="space-y-3">
               <h4 className="font-mono text-sm font-bold text-green-500 uppercase tracking-wide">Recovery</h4>
               <ul className="space-y-2">
                 {analysis.response.recovery && analysis.response.recovery.length > 0 ? (
                   analysis.response.recovery.map((action, i) => (
                     <li key={i} className="flex items-start text-sm text-gray-300 bg-base/50 p-2 rounded border border-hairline">
                       <CheckSquare className="w-4 h-4 text-gray-500 mr-2 shrink-0 mt-0.5" />
                       {action}
                     </li>
                   ))
                 ) : (
                   <li className="text-sm font-mono text-gray-500 italic">No recovery actions.</li>
                 )}
               </ul>
            </div>
         </div>
      </div>
    </div>
  );
};
