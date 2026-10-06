import React, { useEffect, useState } from 'react';
import { fetchModels, fetchRobustness, fetchAblation, fetchComparative } from '../api';

export const ResearchTab: React.FC = () => {
  const [models, setModels] = useState<any[]>([]);
  const [robustness, setRobustness] = useState<any[]>([]);
  const [ablation, setAblation] = useState<any[]>([]);
  const [comparative, setComparative] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetchModels(),
      fetchRobustness(),
      fetchAblation(),
      fetchComparative()
    ]).then(([m, r, a, c]) => {
      setModels(m || []);
      setRobustness(r || []);
      setAblation(a || []);
      setComparative(c);
      setLoading(false);
    }).catch(console.error);
  }, []);

  if (loading) return <div className="animate-pulse text-accent font-mono p-4">Loading research data...</div>;

  return (
    <div className="space-y-6">
      
      {/* Models Performance */}
      <div className="bg-surface border border-hairline rounded-lg p-6">
        <div className="flex justify-between items-start mb-4">
          <h3 className="font-display text-xl text-white">Model Performance (Test Set)</h3>
          <span className="text-xs font-mono px-2 py-1 bg-accent/20 text-accent rounded border border-accent/30 uppercase tracking-widest">Measured</span>
        </div>
        <p className="text-sm text-gray-400 mb-4">
          Strictly held-out performance metrics. High baseline scores reflect dataset-specific feature separability inherent to the collection methodology.
        </p>
        <div className="overflow-x-auto">
          {models.length > 0 ? (
          <table className="w-full text-left font-mono text-sm">
            <thead>
              <tr className="border-b border-hairline text-gray-400">
                <th className="py-2 pr-4">Model</th>
                <th className="py-2 pr-4">ROC AUC</th>
                <th className="py-2 pr-4">Accuracy</th>
                <th className="py-2 pr-4">F1 Macro</th>
                <th className="py-2 pr-4">Inf. Time (ms)</th>
              </tr>
            </thead>
            <tbody>
              {models.map((m, idx) => (
                <tr key={idx} className="border-b border-hairline/50 hover:bg-hairline/20">
                  <td className="py-3 pr-4 text-accent">{m.model}</td>
                  <td className="py-3 pr-4">{Number(m.roc_auc).toFixed(4)}</td>
                  <td className="py-3 pr-4">{Number(m.accuracy).toFixed(4)}</td>
                  <td className="py-3 pr-4">{Number(m.f1_macro).toFixed(4)}</td>
                  <td className="py-3 pr-4">{Number(m.inference_time_ms).toFixed(2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          ) : <p className="text-sm text-gray-500 font-mono italic">Not available</p>}
        </div>
      </div>

      {/* Robustness Stress Test */}
      <div className="bg-surface border border-hairline rounded-lg p-6">
        <div className="flex justify-between items-start mb-4">
          <h3 className="font-display text-xl text-white">Feature-Perturbation Robustness Stress Test</h3>
          <span className="text-xs font-mono px-2 py-1 bg-blue-500/20 text-blue-400 rounded border border-blue-500/30 uppercase tracking-widest">Simulated</span>
        </div>
        <p className="text-sm text-gray-400 mb-4">
          Simulated sensitivity of the primary model to increasing feature noise.
        </p>
        <div className="overflow-x-auto">
          {robustness.length > 0 ? (
          <table className="w-full text-left font-mono text-sm">
            <thead>
              <tr className="border-b border-hairline text-gray-400">
                <th className="py-2 pr-4">Noise Level</th>
                <th className="py-2 pr-4">Accuracy</th>
                <th className="py-2 pr-4">F1 Macro</th>
                <th className="py-2 pr-4">Delta F1</th>
              </tr>
            </thead>
            <tbody>
              {robustness.map((r, idx) => (
                <tr key={idx} className="border-b border-hairline/50 hover:bg-hairline/20">
                  <td className="py-3 pr-4 text-accent">{r.noise_level}</td>
                  <td className="py-3 pr-4">{Number(r.accuracy).toFixed(4)}</td>
                  <td className="py-3 pr-4">{Number(r.f1_macro).toFixed(4)}</td>
                  <td className="py-3 pr-4">{Number(r.delta_f1).toFixed(4)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          ) : <p className="text-sm text-gray-500 font-mono italic">Not available</p>}
        </div>
      </div>

      {/* Correlation Ablation */}
      <div className="bg-surface border border-hairline rounded-lg p-6">
        <div className="flex justify-between items-start mb-4">
          <h3 className="font-display text-xl text-white">Correlation Dimension Ablation</h3>
          <span className="text-xs font-mono px-2 py-1 bg-purple-500/20 text-purple-400 rounded border border-purple-500/30 uppercase tracking-widest">Derived</span>
        </div>
        <p className="text-sm text-gray-400 mb-4">
          Contributions of multi-dimensional bounds to the normalized cluster confidence score.
        </p>
        <div className="overflow-x-auto">
          {ablation.length > 0 ? (
          <table className="w-full text-left font-mono text-sm">
            <thead>
              <tr className="border-b border-hairline text-gray-400">
                <th className="py-2 pr-4">Configuration</th>
                <th className="py-2 pr-4">Correlation Score</th>
                <th className="py-2 pr-4">Edges Formed</th>
                <th className="py-2 pr-4">Interpretation</th>
              </tr>
            </thead>
            <tbody>
              {ablation.map((a, idx) => (
                <tr key={idx} className="border-b border-hairline/50 hover:bg-hairline/20">
                  <td className="py-3 pr-4 text-accent">{a.Configuration}</td>
                  <td className="py-3 pr-4">{Number(a.Correlation_Score).toFixed(4)}</td>
                  <td className="py-3 pr-4">{a.Edges_Formed}</td>
                  <td className="py-3 pr-4">{a.Interpretation}</td>
                </tr>
              ))}
            </tbody>
          </table>
          ) : <p className="text-sm text-gray-500 font-mono italic">Not available</p>}
        </div>
      </div>

      {/* Comparative Forensics */}
      <div className="bg-surface border border-hairline rounded-lg p-6">
        <div className="flex justify-between items-start mb-4">
          <h3 className="font-display text-xl text-white">Comparative: ML-Only vs SecureShield</h3>
          <span className="text-xs font-mono px-2 py-1 bg-blue-500/20 text-blue-400 rounded border border-blue-500/30 uppercase tracking-widest">Simulated</span>
        </div>
        <p className="text-sm text-gray-400 mb-4">
          Evaluation of actionable incidents. Note: Analyzed on a sampled subset due to the lack of native forensic telemetry streams in the dataset.
        </p>
        <div className="overflow-x-auto">
          {comparative ? (
          <div className="grid grid-cols-2 gap-4 font-mono text-sm">
            <div className="bg-base p-4 rounded border border-hairline">
              <p className="text-gray-400 mb-2">Evaluation Limitation</p>
              <p className="text-white text-xs">{comparative.Limitation}</p>
            </div>
            <div className="bg-base p-4 rounded border border-hairline">
              <p className="text-gray-400 mb-2">Subset Size</p>
              <p className="text-xl text-accent">{comparative.Tested_Subset_Size}</p>
            </div>
            <div className="bg-base p-4 rounded border border-hairline">
              <p className="text-gray-400 mb-2">ML FPs Sampled</p>
              <p className="text-xl text-white">{comparative.ML_Only_FPs_Sampled}</p>
            </div>
            <div className="bg-base p-4 rounded border border-hairline">
              <p className="text-gray-400 mb-2">Actionable SS FPs</p>
              <p className="text-xl text-accent">{comparative.SecureShield_Actionable_FPs}</p>
            </div>
            <div className="bg-base p-4 rounded border border-hairline">
              <p className="text-gray-400 mb-2">ML TPs Sampled</p>
              <p className="text-xl text-white">{comparative.ML_Only_TPs_Sampled}</p>
            </div>
            <div className="bg-base p-4 rounded border border-hairline">
              <p className="text-gray-400 mb-2">Actionable SS TPs</p>
              <p className="text-xl text-accent">{comparative.SecureShield_Actionable_TPs}</p>
            </div>
          </div>
          ) : <p className="text-sm text-gray-500 font-mono italic">Not available</p>}
        </div>
      </div>
      
    </div>
  );
};
