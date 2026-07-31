package auth

import "context"

// AuthzInput is one authorization question.
type AuthzInput struct {
	// Permissions is the actor's flat permission set.
	Permissions []string
	// SubjectID is the acting principal's id.
	SubjectID string
	// SelfEligible reports whether the principal is one that can own
	// resources. A reserved non-user principal is not, so no `:self`
	// grant can admit it.
	SelfEligible bool
	Action       string
	// ResourceID is the target, when the caller knows it. Empty means
	// the target is not identified at this layer — a creation, or the
	// interceptor's coarse pass before the handler resolves the row.
	ResourceID string
}

// Authorize decides one permission question.
//
// Four ways to pass, in the order the tiers are written in a role:
//
//  1. the unrestricted permission;
//  2. `:self` with no identified resource — a creation whose ownership
//     the handler pins;
//  3. `:self` where the resource IS the actor;
//  4. `:assigned`, which admits the request so the handler's
//     assigned-owner filter can decide which rows are visible.
//
// Tiers 2 and 3 require a principal that can own resources.
func Authorize(input AuthzInput) bool {
	for _, p := range input.Permissions {
		if p == input.Action {
			return true
		}
		if p == input.Action+":self" && input.SelfEligible {
			if input.ResourceID == "" || input.ResourceID == input.SubjectID {
				return true
			}
		}
		if p == input.Action+":assigned" {
			return true
		}
	}
	return false
}

// AuthorizeContext answers the same question for the actor on ctx.
func AuthorizeContext(ctx context.Context, action, resourceID string) bool {
	user, ok := UserFromContext(ctx)
	if !ok {
		return false
	}
	return Authorize(AuthzInput{
		Permissions:  user.Permissions,
		SubjectID:    user.ID,
		SelfEligible: user.CanOwnResources(),
		Action:       action,
		ResourceID:   resourceID,
	})
}
