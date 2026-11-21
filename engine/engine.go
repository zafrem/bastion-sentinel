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

// Engine orchestrates prompt injection detection and metadata validation. With a policy configured it
// holds one set of controls per profile and routes each request by its tenant; without one it holds
// just the base configuration and behaves exactly as a single engine.
type Engine struct {
	byProfile map[string]*inputEngine // "" is the base configuration
	tenants   map[string]string
	def       string
}

// inputEngine is the controls of one profile.
type inputEngine struct {
	promptDetector    *prompt.Detector
	metadataValidator *metadata.Validator
	noticeDetail      string
}

// New builds the engines for the base configuration and for every declared policy profile. A profile
// that cannot be built (for example a bad judge setting) is an error here, not at its first request.
func New(cfg *config.Config) (*Engine, error) {
	if err := cfg.CheckPolicy(); err != nil {
		return nil, err
	}
	e := &Engine{byProfile: map[string]*inputEngine{}, tenants: cfg.Policy.Tenants, def: cfg.Policy.DefaultProfile}
	for _, name := range append([]string{""}, cfg.ProfileNames()...) {
		pc, err := cfg.ProfileConfig(name)
		if err != nil {
			return nil, err
		}
		ie, err := newInputEngine(pc)
		if err != nil {
			if name != "" {
				return nil, fmt.Errorf("profile %q: %w", name, err)
			}
			return nil, err
		}
		e.byProfile[name] = ie
	}
	return e, nil
}

// profileFor is the profile a tenant is held to.
func (e *Engine) profileFor(tenant string) string {
	if p, ok := e.tenants[tenant]; ok {
		return p
	}
	return e.def
}

func newInputEngine(cfg *config.Config) (*inputEngine, error) {
	scorer, err := ml.NewScorerChecked(cfg.PromptInjection.MLModel)
	if err != nil {
		return nil, err
	}

	pd, err := prompt.New(cfg.PromptInjection, scorer)
	if err != nil {
		return nil, fmt.Errorf("prompt detector: %w", err)
	}

	mv, err := metadata.New(cfg.MetadataValidation)
	if err != nil {
		return nil, fmt.Errorf("metadata validator: %w", err)
	}

	return &inputEngine{
		promptDetector:    pd,
		metadataValidator: mv,
		noticeDetail:      cfg.UserNotice.Detail,
	}, nil
}

// Validate holds the request to the profile its tenant maps to and says which one in the response.
func (e *Engine) Validate(req types.ValidateRequest) types.ValidateResponse {
	profile := e.profileFor(req.Metadata["tenant_id"])
	resp := e.byProfile[profile].Validate(req)
	resp.Profile = profile
	return resp
}

func (e *inputEngine) Validate(req types.ValidateRequest) types.ValidateResponse {
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
