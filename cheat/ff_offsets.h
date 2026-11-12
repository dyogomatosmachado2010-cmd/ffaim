// FreeFire iOS (com.privateproject.ff2018.v128, 1.28.0) - il2cpp offsets
// arm64 Mach-O, __TEXT vmaddr 0x100000000, RVA == file offset
// gerado de global-metadata.dat v23 + binario; ver tools/offsets.py
#pragma once
#include <stdint.h>

// ---- base ----
// endereco em runtime = base_do_modulo + RVA   (base = _dyld_get_image_header do freefireth)
#define FF_IMAGE_VMADDR 0x100000000ULL

// ---- metodos (RVA) ----
enum : uintptr_t {
    RVA_Player_LateUpdate            = 0x9093E4,  // void Player::LateUpdate()
    RVA_Player_UpdateAiming          = 0x9269AC,  // void Player::UpdateAiming(?, Quaternion)
    RVA_Player_IsLocalPlayer         = 0x8EA308,  // bool Player::IsLocalPlayer()
    RVA_Player_IsLocalTeammate       = 0x916F44,  // bool Player::IsLocalTeammate()
    RVA_Player_GetHeadPosition       = 0x9291B4,  // Vector3 Player::GetHeadPosition()
    RVA_Player_GetHipPosition        = 0x922B84,  // Vector3 Player::GetHipPosition()
    RVA_Player_GetAimStartPostion    = 0x927208,  // Vector3 Player::get_AimStartPostion()
    RVA_Player_GetAimRotation        = 0x8FB818,  // Quaternion Player::GetAimRotation()
    RVA_Player_SetAimRotation        = 0x909D3C,  // void Player::SetAimRotation(Quaternion)
    RVA_Player_GetCC_TopPosition     = 0x9256CC,  // Vector3 Player::GetCharacterControllerTopPosition()
    RVA_Player_GetUserID             = 0x91FD50,  // ulong  Player::get_UserID()
    RVA_Player_GetPlayerID           = 0x8DCDF8,  // int    Player::get_PlayerID()
    RVA_Player_GetTeamIndex          = 0x930880,  // int    Player::get_TeamIndex()

    RVA_Entity_GetIsDead             = 0x75EF68,  // bool AttackableEntity::get_IsDead()
    RVA_Entity_IsVisible             = 0x75F0D4,  // bool AttackableEntity::IsVisible()

    RVA_Transform_GetPosition        = 0x12B0914, // Vector3 Transform::get_position()
    RVA_Transform_GetParent          = 0x12B123C, // Transform* Transform::get_parent()
    RVA_Transform_GetForward         = 0x12B0E94, // Vector3 Transform::get_forward()

    RVA_Quaternion_LookRotation      = 0x1293130, // Quaternion Quaternion::LookRotation(Vector3, Vector3)
    RVA_Quaternion_Slerp             = 0x1293240, // Quaternion Quaternion::Slerp(Quaternion, Quaternion, float)

    RVA_Camera_GetMain               = 0x124D8B0, // Camera* Camera::get_main()
    RVA_Camera_WorldToScreenPoint    = 0x124D434, // Vector3 Camera::WorldToScreenPoint(Vector3)
    RVA_Camera_GetPixelHeight        = 0x124D060, // int Camera::get_pixelHeight()
    RVA_Camera_GetTransform          = 0x1251F4C, // Transform* Component::get_transform()

    RVA_Screen_GetWidth              = 0x129C094, // int Screen::get_width()
    RVA_Screen_GetHeight             = 0x129C0EC, // int Screen::get_height()
};

// ---- campos (offset absoluto, ja inclui o header de 0x10) ----
enum : uint32_t {
    OFF_Player_UserID           = 0x068,  // ulong
    OFF_Player_PlayerID         = 0x070,  // int
    OFF_Player_TeamIndex        = 0x074,  // int
    OFF_Player_AimRotation      = 0x114,  // Quaternion (x,y,z,w) - a mira que a camera segue
    OFF_Player_EAimAssist       = 0x134,  // enum
    OFF_Player_WeaponMountTF    = 0x150,  // Transform*
    OFF_Player_HeadTF           = 0x158,  // Transform*
    OFF_Player_HipTF            = 0x160,  // Transform*
    OFF_Player_LeftAnkleTF      = 0x180,  // Transform*
    OFF_Player_RightAnkleTF     = 0x188,  // Transform*
    OFF_Player_LeftToeTF        = 0x190,  // Transform*
    OFF_Player_RightToeTF       = 0x198,  // Transform*
    OFF_Player_CharController   = 0x0B8,  // CharacterController*
    OFF_Player_Attributes       = 0x1B0,  // PlayerAttributes*
    OFF_Player_AvatarManager    = 0x1B8,  // AvatarManager*
    OFF_Player_AnimComponent    = 0x1A8,  // NewPlayerAnimationSystemComponent*
    OFF_Player_IsClientBot      = 0x0A0,  // bool

    OFF_Entity_IsDead           = 0x044,  // bool
    OFF_Entity_Collider         = 0x048,  // Collider*
    OFF_Entity_AimingCollider   = 0x050,  // Collider*

    OFF_CamCtrl_Camera          = 0x018,  // Camera*
    OFF_CamCtrl_TargetEntity    = 0x020,  // entity do jogador local

    OFF_Transform_Parent        = 0x018,  // Transform* (campo interno do Component)
    OFF_Object_CachedPtr        = 0x010,  // IntPtr -> objeto nativo Unity
};

// ---- tamanhos de instancia ----
enum : uint32_t {
    SZ_Player                   = 0x620,
    SZ_PlayerNetwork            = 0x650,
    SZ_PlayerAttributes         = 0x060,
    SZ_AttackableEntity         = 0x058,
    SZ_CameraControllerBase     = 0x038,
    SZ_FollowCamera             = 0x0D0,
    SZ_HitDetectColliderHelper  = 0x030,
    SZ_BoneNameRef              = 0x028,
};

// ---- bone: no Player os Transform das bones ficam nesse bloco ----
// 0x150 WeaponMount | 0x158 Head | 0x160 Hip | 0x180 L-Ankle | 0x188 R-Ankle | 0x190 L-Toe | 0x198 R-Toe
// Neck nao tem campo proprio: HeadTF->parent (get_parent 0x12B123C) -> get_position.
