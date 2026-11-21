package engine

import (
	"fmt"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/zafrem/bastion-sentinel/config"
	"github.com/zafrem/bastion-sentinel/ml"
	"github.com/zafrem/bastion-sentinel/types"
	"github.com/zafrem/bastion-sentinel/validators/metadata"
	"github.com/zafrem/bastion-sentinel/validators/prompt"
)

// Engine orchestrates prompt injection detection and metadata validation.
type Engine struct {
	promptDetector    *prompt.Detector
	metadataValidator *metadata.Validator
	noticeDetail      string
}

func New(cfg *config.Config) (*Engine, error) {
	scorer := ml.NewScorer(cfg.PromptInjection.MLModel)

	pd, err := prompt.New(cfg.PromptInjection, scorer)
	if err != nil {
		return nil, fmt.Errorf("prompt detector: %w", err)
	}

	mv, err := metadata.New(cfg.MetadataValidation)
	if err != nil {
		return nil, fmt.Errorf("metadata validator: %w", err)
	}

	return &Engine{
		promptDetector:    pd,
		metadataValidator: mv,
		noticeDetail:      cfg.UserNotice.Detail,
	}, nil
}

func (e *Engine) Validate(req types.ValidateRequest) types.ValidateResponse {
	start := time.Now()

	normalized := norm.NFC.String(req.Query)

	tenant, user := req.Metadata["tenant_id"], req.Metadata["user_id"]
	promptResult := e.promptDetector.DetectExcept(normalized, func(id string) (string, bool) {
		return allowed("sentinel.in:"+id, tenant, user)
	})
	metaResult := e.metadataValidator.Validate(req.Metadata, req.Query)

	status := types.StatusPassed
	if promptResult.Status == types.StatusBlocked || metaResult.Status == types.StatusBlocked {
		status = types.StatusBlocked
	}

	var notice *types.UserNotice
	if status == types.StatusBlocked {
		code := types.CodeInjectionSuspected
		if promptResult.Status != types.StatusBlocked {
			code = types.CodeMetadataInvalid
		}
		notice = types.NewNotice(e.noticeDetail, types.NoticeBlocked, code, req.RequestID, 0)
	}

	return types.ValidateResponse{
		Notice:            notice,
		ExceptionsApplied: promptResult.ExceptionIDs,
		RequestID:         req.RequestID,
		Status:            status,
		Timestamp:         time.Now().UTC(),
		PromptCheck:       promptResult,
		MetadataCheck:     metaResult,
		ExtractedData: types.ExtractedData{
			TenantID:     req.Metadata["tenant_id"],
			UserID:       req.Metadata["user_id"],
			CleanedQuery: normalized,
		},
		ProcessingTimeMs: float64(time.Since(start).Microseconds()) / 1000.0,
	}
}
