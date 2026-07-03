package profile

// ProfileStore 定义 Builder 需要的 store 数据访问接口
// store.Store 隐式实现了此接口
type ProfileStore interface {
	AggregateProfileData(ip string) (*ProfileData, error)
	AggregateProfileByIP(eng *Engine, ip string) (*AttackerProfile, error)
	AggregateAllProfiles(eng *Engine, tagFilter string) ([]*AttackerProfile, error)
	GetCountermeasureSummariesByIP(ip string) ([]CountermeasureSummary, error)
}

// Builder 攻击者画像构建器，聚合 store 数据并生成画像
type Builder struct {
	store  ProfileStore
	engine *Engine
}

// NewBuilder 创建画像构建器
func NewBuilder(st ProfileStore) *Builder {
	return &Builder{
		store:  st,
		engine: NewEngine(),
	}
}

// BuildProfile 构建单个攻击者画像
// 查询：connections、attacks、fingerprints、countermeasures（通过 store 聚合）
func (b *Builder) BuildProfile(ip string) (*AttackerProfile, error) {
	profile, err := b.store.AggregateProfileByIP(b.engine, ip)
	if err != nil {
		return nil, err
	}

	// 附加反制措施摘要
	summaries, err := b.store.GetCountermeasureSummariesByIP(ip)
	if err == nil {
		profile.Countermeasures = summaries
	}

	return profile, nil
}

// BuildAllProfiles 返回所有攻击者画像列表
func (b *Builder) BuildAllProfiles(limit int) ([]*AttackerProfile, error) {
	profiles, err := b.store.AggregateAllProfiles(b.engine, "")
	if err != nil {
		return nil, err
	}

	// 应用 limit
	if limit > 0 && limit < len(profiles) {
		profiles = profiles[:limit]
	}

	// 附加每个画像的反制措施摘要
	for _, p := range profiles {
		summaries, err := b.store.GetCountermeasureSummariesByIP(p.IP)
		if err == nil {
			p.Countermeasures = summaries
		}
	}

	return profiles, nil
}
