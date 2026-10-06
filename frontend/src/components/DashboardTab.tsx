import React from 'react';
import type { AnalysisResponse } from '../api';
import { ProvenanceBadge } from './ProvenanceBadge';
import { AlertTriangle, ShieldCheck, Activity, Target } from 'lucide-react';

interface Props {
  analysis: AnalysisResponse;
}

export const DashboardTab: React.FC<Props> = ({ analysis }) => {
  const isMalicious = analysis.prediction.label === 'malicious';
  const confidence = (analysis.prediction.confidence * 100).toFixed(1);

  return (
    <div className="space-y-6">
      {/* Top row cards */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-surface border border-hairline p-5 rounded flex flex-col relative overflow-hidden">
          <div className="flex justify-between items-start mb-4">
            <h3 className="mono-label text-gray-400">ML Prediction</h3>
            <ProvenanceBadge provenance={analysis.prediction.provenance} />
          </div>
          <div className="flex items-center mt-auto">
            {isMalicious ? (
              <AlertTriangle className="w-8 h-8 text-accent mr-3" />
            ) : (
              <ShieldCheck className="w-8 h-8 text-green-500 mr-3" />
            )}
            <div>
              <div className={`font-display text-3xl font-bold uppercase tracking-wider ${isMalicious ? 'text-accent' : 'text-green-500'}`}>
                {analysis.prediction.label}
              </div>
              <div className="text-sm text-gray-400 mt-1 font-mono">
                Confidence: {confidence}% | {analysis.prediction.model}
              </div>
            </div>
          </div>
        </div>

        <div className="bg-surface border border-hairline p-5 rounded flex flex-col relative">
          <div className="flex justify-between items-start mb-4">
            <h3 className="mono-label text-gray-400">Risk Assessment</h3>
            <ProvenanceBadge provenance={analysis.risk.provenance} />
          </div>
          <div className="flex items-center mt-auto">
            <Activity className="w-8 h-8 text-gray-400 mr-3" />
            <div>
              <div className="font-display text-3xl font-bold text-white tracking-wider">
                {analysis.risk.score}/100
              </div>
              <div className="text-sm text-gray-400 mt-1 font-mono">
                Severity: {analysis.risk.severity}
              </div>
            </div>
          </div>
        </div>

        <div className="bg-surface border border-hairline p-5 rounded flex flex-col relative">
          <div className="flex justify-between items-start mb-4">
            <h3 className="mono-label text-gray-400">MITRE ATT&CK</h3>
            <ProvenanceBadge provenance="DERIVED" />
          </div>
          <div className="flex items-center mt-auto">
            <Target className="w-8 h-8 text-gray-400 mr-3" />
            <div>
              <div className="font-display text-3xl font-bold text-white tracking-wider">
                {analysis.mitre.length}
              </div>
              <div className="text-sm text-gray-400 mt-1 font-mono">
                Techniques Mapped
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Highlights */}
      <div className="grid grid-cols-2 gap-4">
         <div className="bg-surface border border-hairline p-5 rounded">
            <h3 className="mono-label text-gray-400 mb-4 border-b border-hairline pb-2">Top Forensic Evidence</h3>
            {analysis.evidence.length > 0 ? (
              <div className="space-y-3 mt-4">
                {analysis.evidence.slice(0, 3).map((ev, i) => (
                  <div key={i} className="flex justify-between items-start p-3 bg-base/50 rounded border border-hairline">
                     <div>
                       <div className="text-xs font-mono text-gray-500 mb-1">{ev.id} | {ev.type}</div>
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

         <div className="bg-surface border border-hairline p-5 rounded">
            <h3 className="mono-label text-gray-400 mb-4 border-b border-hairline pb-2">Top Influential Features (SHAP)</h3>
            <div className="space-y-2 mt-4">
               {analysis.shap.slice(0, 5).map((sv, i) => (
                 <div key={i} className="flex justify-between items-center text-sm font-mono p-2 border-b border-hairline/50 last:border-0">
                    <span className="text-gray-300">{sv.feature}</span>
                    <span className={sv.direction === 'malicious' ? 'text-accent' : 'text-blue-400'}>
                      {sv.shap_contribution > 0 ? '+' : ''}{sv.shap_contribution.toFixed(4)}
                    </span>
                 </div>
               ))}
            </div>
         </div>
      </div>
    </div>
  );
};
