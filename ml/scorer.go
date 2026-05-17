package ml

// Scorer is the interface for ML-based prompt injection risk scoring.
// Implementations return a risk probability in [0.0, 1.0].
type Scorer interface {
	Score(query string) (float64, error)
}

// OnnxStub satisfies Scorer as a placeholder until a real ONNX model is loaded.
// It always returns 0.0, meaning the rule-based engines carry all scoring weight.
// Replace with a real implementation using github.com/yalue/onnxruntime_go or equivalent.
type OnnxStub struct{}

func (s *OnnxStub) Score(_ string) (float64, error) {
	return 0.0, nil
}
