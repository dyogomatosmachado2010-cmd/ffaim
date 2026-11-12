// ffpanel.mm - painel flutuante (UIKit), overlay de ESP e gesto de 3 dedos x3.
// tudo na main thread; o core publica o snapshot do ESP por lock (ffaim.mm).
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/runtime.h>
#import <math.h>
#import "ffaim.h"
#include "ffhook.h"

#define PANEL_W 268.0f
#define HEADER_H 44.0f

// paleta Lunar: preto quente de fundo, bege lunar no texto e nos controles
#define LC_BG     [UIColor colorWithRed:0.043 green:0.041 blue:0.039 alpha:0.97]
#define LC_SURF   [UIColor colorWithRed:0.082 green:0.078 blue:0.071 alpha:1.0]
#define LC_BEIGE  [UIColor colorWithRed:0.910 green:0.859 blue:0.749 alpha:1.0]
#define LC_DIM    [UIColor colorWithRed:0.639 green:0.596 blue:0.510 alpha:1.0]
#define LC_FAINT  [UIColor colorWithRed:0.376 green:0.353 blue:0.306 alpha:1.0]
#define LC_TEXT   [UIColor colorWithRed:0.898 green:0.886 blue:0.855 alpha:1.0]
#define LC_LINE   [UIColor colorWithRed:0.910 green:0.859 blue:0.749 alpha:0.16]
#define LC_TRACK  [UIColor colorWithWhite:1.0 alpha:0.12]

// ---------------------------------------------------------------- esp view

@interface FFEspView : UIView
@end

@implementation FFEspView {
    CADisplayLink *_link;
}

- (instancetype)initWithFrame:(CGRect)frame {
    if ((self = [super initWithFrame:frame])) {
        self.backgroundColor = [UIColor clearColor];
        self.opaque = NO;
        self.userInteractionEnabled = NO;
        self.contentMode = UIViewContentModeRedraw;
        _link = [CADisplayLink displayLinkWithTarget:self selector:@selector(onTick)];
        [_link addToRunLoop:[NSRunLoop mainRunLoop] forMode:NSRunLoopCommonModes];
    }
    return self;
}

- (void)onTick {
    if (!self.hidden && g_cfg.esp) [self setNeedsDisplay];
}

static void drawText(NSString *s, CGPoint p, UIColor *c) {
    UIFont *f = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightBold];
    NSDictionary *sh = @{ NSFontAttributeName: f,
                          NSForegroundColorAttributeName: [UIColor colorWithWhite:0 alpha:0.85] };
    NSDictionary *fg = @{ NSFontAttributeName: f,
                          NSForegroundColorAttributeName: c };
    [s drawAtPoint:CGPointMake(p.x + 1, p.y + 1) withAttributes:sh];
    [s drawAtPoint:p withAttributes:fg];
}

- (void)drawRect:(CGRect)rect {
    if (!g_cfg.esp) return;

    FFEspBox boxes[64];
    int n = ff_esp_snapshot(boxes, 64);
    if (n <= 0) return;

    const CGFloat W = self.bounds.size.width;
    const CGFloat H = self.bounds.size.height;

    CGContextRef ctx = UIGraphicsGetCurrentContext();
    CGContextSetLineWidth(ctx, 1.4f);

    for (int i = 0; i < n; i++) {
        const FFEspBox *b = &boxes[i];

        // normalizado (y pra cima) -> tela (y pra baixo)
        CGFloat hx = b->hx * W;
        CGFloat hy = (1.0f - b->hy) * H;
        CGFloat fx = b->fx * W;
        CGFloat fy = (1.0f - b->fy) * H;

        CGFloat h = fy - hy;
        if (h < 4.0f) continue;
        CGFloat bw = h * 0.45f;
        CGFloat cx = (hx + fx) * 0.5f;
        CGRect box = CGRectMake(cx - bw * 0.5f, hy, bw, h);

        UIColor *col = [UIColor colorWithRed:0.910 green:0.859 blue:0.749 alpha:0.95];

        if (g_cfg.drawBox) {
            CGContextSetStrokeColorWithColor(ctx, col.CGColor);
            CGContextStrokeRect(ctx, box);
            // tick no topo/bottom pra leitura rapida
            CGContextMoveToPoint(ctx, box.origin.x, box.origin.y + h * 0.5f);
            CGContextAddLineToPoint(ctx, box.origin.x - 4, box.origin.y + h * 0.5f);
            CGContextMoveToPoint(ctx, CGRectGetMaxX(box), box.origin.y + h * 0.5f);
            CGContextAddLineToPoint(ctx, CGRectGetMaxX(box) + 4, box.origin.y + h * 0.5f);
            CGContextStrokePath(ctx);
        }

        if (g_cfg.drawLine) {
            CGContextSetStrokeColorWithColor(ctx, [UIColor colorWithRed:0.910 green:0.859 blue:0.749 alpha:0.30].CGColor);
            CGContextMoveToPoint(ctx, W * 0.5f, H - 2);
            CGContextAddLineToPoint(ctx, cx, fy);
            CGContextStrokePath(ctx);
        }

        CGFloat ty = hy - 14;
        if (ty < 2) ty = 2;

        if (g_cfg.drawName && b->id != 0) {
            drawText([NSString stringWithFormat:@"#%d", b->id],
                     CGPointMake(cx - bw * 0.5f, ty), col);
        }
        if (g_cfg.drawDist) {
            drawText([NSString stringWithFormat:@"%.0fm", b->dist],
                     CGPointMake(cx - bw * 0.5f, CGRectGetMaxY(box) + 2), col);
        }
    }
}

@end

// ---------------------------------------------------------------- panel

@interface FFPanelView : UIView
- (CGFloat)fullHeight;
- (void)refreshStatus;
@end

@implementation FFPanelView {
    UIView      *_header;
    UIView      *_body;
    CGPoint      _dragStart;
    BOOL         _minimized;
    CGFloat      _fullH;

    UISwitch    *_aimSw;
    UISwitch    *_espSw;
    UISwitch    *_teamSw;
    UISlider    *_fovSl;
    UISlider    *_smoothSl;
    UILabel     *_fovVal;
    UILabel     *_smoothVal;
    UILabel     *_status;
    UISegmentedControl *_boneSeg;
}

- (UILabel *)label:(NSString *)t frame:(CGRect)f {
    UILabel *l = [[UILabel alloc] initWithFrame:f];
    l.text = t;
    l.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    l.textColor = LC_TEXT;
    l.backgroundColor = [UIColor clearColor];
    return l;
}

- (UILabel *)valueLabel:(CGRect)f {
    UILabel *l = [[UILabel alloc] initWithFrame:f];
    l.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightBold];
    l.textColor = LC_BEIGE;
    l.textAlignment = NSTextAlignmentRight;
    l.backgroundColor = [UIColor clearColor];
    return l;
}

- (UISwitch *)mkSwitch:(CGRect)f on:(BOOL)on {
    UISwitch *s = [[UISwitch alloc] initWithFrame:f];
    s.transform = CGAffineTransformMakeScale(0.78, 0.78);
    s.onTintColor = LC_BEIGE;
    s.on = on;
    [s addTarget:self action:@selector(onSwitch) forControlEvents:UIControlEventValueChanged];
    return s;
}

- (UISlider *)mkSlider:(CGRect)f min:(float)mn max:(float)mx val:(float)v sel:(SEL)sel {
    UISlider *s = [[UISlider alloc] initWithFrame:f];
    s.minimumValue = mn;
    s.maximumValue = mx;
    s.value = v;
    s.minimumTrackTintColor = LC_BEIGE;
    s.maximumTrackTintColor = LC_TRACK;
    s.thumbTintColor = LC_BEIGE;
    [s addTarget:self action:sel forControlEvents:UIControlEventValueChanged];
    [s addTarget:self action:@selector(onCommit) forControlEvents:
        UIControlEventTouchUpInside | UIControlEventTouchUpOutside];
    return s;
}

- (instancetype)initWithFrame:(CGRect)frame {
    if ((self = [super initWithFrame:frame])) {
        self.backgroundColor = LC_BG;
        self.layer.cornerRadius = 18;
        self.layer.masksToBounds = YES;
        self.layer.borderWidth = 1.0;
        self.layer.borderColor = LC_LINE.CGColor;

        [self buildHeader];
        [self buildBody];

        self.frame = CGRectMake(frame.origin.x, frame.origin.y, PANEL_W, _fullH);
    }
    return self;
}

- (CGFloat)fullHeight { return _fullH; }

- (void)buildHeader {
    _header = [[UIView alloc] initWithFrame:CGRectMake(0, 0, PANEL_W, HEADER_H)];
    _header.backgroundColor = LC_SURF;
    [self addSubview:_header];

    UILabel *moon = [[UILabel alloc] initWithFrame:CGRectMake(12, 6, 20, 22)];
    moon.text = @"☾";
    moon.font = [UIFont systemFontOfSize:17 weight:UIFontWeightRegular];
    moon.textColor = LC_BEIGE;
    moon.backgroundColor = [UIColor clearColor];
    [_header addSubview:moon];

    UILabel *t = [self label:@"Lunar Mod 1.0" frame:CGRectMake(34, 5, PANEL_W - 84, 20)];
    t.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightBold];
    t.textColor = LC_BEIGE;
    [_header addSubview:t];

    UILabel *sub = [self label:@"FF 1.28  ·  3 dedos x3"
                         frame:CGRectMake(34, 23, PANEL_W - 84, 14)];
    sub.font = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightRegular];
    sub.textColor = LC_FAINT;
    [_header addSubview:sub];

    UIButton *min = [UIButton buttonWithType:UIButtonTypeSystem];
    min.frame = CGRectMake(PANEL_W - 40, (HEADER_H - 30) * 0.5f, 30, 30);
    [min setTitle:@"–" forState:UIControlStateNormal];
    min.titleLabel.font = [UIFont systemFontOfSize:22 weight:UIFontWeightBold];
    [min setTitleColor:LC_BEIGE forState:UIControlStateNormal];
    [min addTarget:self action:@selector(onMinimize) forControlEvents:UIControlEventTouchUpInside];
    [_header addSubview:min];

    UIView *sep = [[UIView alloc] initWithFrame:CGRectMake(0, HEADER_H - 0.5f, PANEL_W, 0.5f)];
    sep.backgroundColor = LC_LINE;
    [_header addSubview:sep];

    UIPanGestureRecognizer *pan =
        [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(onPan:)];
    [_header addGestureRecognizer:pan];
}

- (void)buildBody {
    CGFloat y = 8;
    _body = [[UIView alloc] initWithFrame:CGRectMake(0, HEADER_H, PANEL_W, 10)];
    [self addSubview:_body];

    // aimbot
    [_body addSubview:[self label:@"Aimbot" frame:CGRectMake(16, y, 160, 30)]];
    _aimSw = [self mkSwitch:CGRectMake(PANEL_W - 16 - 51, y + 1, 51, 31) on:g_cfg.aimbot];
    [_body addSubview:_aimSw];
    y += 36;

    // esp
    [_body addSubview:[self label:@"ESP" frame:CGRectMake(16, y, 160, 30)]];
    _espSw = [self mkSwitch:CGRectMake(PANEL_W - 16 - 51, y + 1, 51, 31) on:g_cfg.esp];
    [_body addSubview:_espSw];
    y += 38;

    // fov
    [_body addSubview:[self label:@"FOV" frame:CGRectMake(16, y, 80, 18)]];
    _fovVal = [self valueLabel:CGRectMake(PANEL_W - 72, y, 56, 18)];
    _fovVal.text = [NSString stringWithFormat:@"%.0f°", g_cfg.fov];
    [_body addSubview:_fovVal];
    y += 20;
    _fovSl = [self mkSlider:CGRectMake(16, y, PANEL_W - 32, 26)
                        min:5 max:180 val:g_cfg.fov sel:@selector(onFov)];
    [_body addSubview:_fovSl];
    y += 34;

    // smooth
    [_body addSubview:[self label:@"Smooth" frame:CGRectMake(16, y, 80, 18)]];
    _smoothVal = [self valueLabel:CGRectMake(PANEL_W - 72, y, 56, 18)];
    _smoothVal.text = [NSString stringWithFormat:@"%.0f%%", g_cfg.smooth * 100];
    [_body addSubview:_smoothVal];
    y += 20;
    _smoothSl = [self mkSlider:CGRectMake(16, y, PANEL_W - 32, 26)
                          min:0 max:1 val:g_cfg.smooth sel:@selector(onSmooth)];
    [_body addSubview:_smoothSl];
    y += 34;

    // bone
    _boneSeg = [[UISegmentedControl alloc] initWithItems:@[@"Head", @"Neck", @"Chest", @"Hip"]];
    _boneSeg.frame = CGRectMake(16, y, PANEL_W - 32, 28);
    _boneSeg.selectedSegmentIndex = g_cfg.bone;
    _boneSeg.tintColor = LC_BEIGE;
    if (@available(iOS 13.0, *)) _boneSeg.selectedSegmentTintColor = LC_BEIGE;
    [_boneSeg setTitleTextAttributes:@{
        NSForegroundColorAttributeName: LC_DIM,
        NSFontAttributeName: [UIFont systemFontOfSize:11 weight:UIFontWeightSemibold]
    } forState:UIControlStateNormal];
    [_boneSeg setTitleTextAttributes:@{
        NSForegroundColorAttributeName: [UIColor colorWithRed:0.06 green:0.05 blue:0.04 alpha:1.0],
        NSFontAttributeName: [UIFont systemFontOfSize:11 weight:UIFontWeightBold]
    } forState:UIControlStateSelected];
    [_boneSeg addTarget:self action:@selector(onBone) forControlEvents:UIControlEventValueChanged];
    [_body addSubview:_boneSeg];
    y += 38;

    // team
    [_body addSubview:[self label:@"Team check" frame:CGRectMake(16, y, 160, 30)]];
    _teamSw = [self mkSwitch:CGRectMake(PANEL_W - 16 - 51, y + 1, 51, 31) on:g_cfg.teamCheck];
    [_body addSubview:_teamSw];
    y += 36;

    UILabel *hint = [self label:@"☾ 3 dedos x3 abre/fecha"
                         frame:CGRectMake(16, y, PANEL_W - 32, 16)];
    hint.font = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightRegular];
    hint.textColor = LC_FAINT;
    [_body addSubview:hint];
    y += 18;

    _status = [self label:@"" frame:CGRectMake(16, y, PANEL_W - 32, 14)];
    _status.font = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightRegular];
    _status.textColor = LC_DIM;
    _status.adjustsFontSizeToFitWidth = YES;
    _status.minimumScaleFactor = 0.7;
    [_body addSubview:_status];
    y += 16;

    _body.frame = CGRectMake(0, HEADER_H, PANEL_W, y);
    _fullH = HEADER_H + y;
    [self refreshStatus];
}

// diagnostico na tela: o hook do LateUpdate e o que decide se aimbot/esp
// funcionam. se ele foi recusado, o motivo aparece aqui e o jogo roda normal.
- (void)refreshStatus {
    if (!_status) return;
    NSString *s;
    if (!g_core_base) {
        s = @"base: nao achou freefireth";
    } else if (!g_core_ready) {
        s = [NSString stringWithFormat:@"hook: %s", ff_hook_last_error];
    } else if (g_core_hits > 0) {
        s = [NSString stringWithFormat:@"hook:%s/%d  p:%d  t:%d",
             g_core_mode, g_core_hits, g_core_players, g_core_ticks];
    } else {
        s = [NSString stringWithFormat:@"hook:%s  p:%d  t:%d",
             g_core_mode, g_core_players, g_core_ticks];
    }
    _status.text = s;
}

- (void)onSwitch {
    g_cfg.aimbot = _aimSw.on;
    g_cfg.esp = _espSw.on;
    g_cfg.teamCheck = _teamSw.on;
    ff_config_save();
}

- (void)onFov {
    g_cfg.fov = _fovSl.value;
    _fovVal.text = [NSString stringWithFormat:@"%.0f°", g_cfg.fov];
}

- (void)onSmooth {
    g_cfg.smooth = _smoothSl.value;
    _smoothVal.text = [NSString stringWithFormat:@"%.0f%%", g_cfg.smooth * 100];
}

- (void)onCommit { ff_config_save(); }

- (void)onBone {
    g_cfg.bone = (int)_boneSeg.selectedSegmentIndex;
    ff_config_save();
}

- (void)onMinimize {
    _minimized = !_minimized;
    CGRect f = self.frame;
    if (_minimized) {
        _body.hidden = YES;
        f.size.height = HEADER_H;
    } else {
        _body.hidden = NO;
        f.size.height = _fullH;
    }
    [UIView animateWithDuration:0.18 animations:^{ self.frame = f; }];
}

- (void)onPan:(UIPanGestureRecognizer *)g {
    CGPoint t = [g translationInView:self.superview];
    if (g.state == UIGestureRecognizerStateBegan) _dragStart = self.center;
    CGPoint c = CGPointMake(_dragStart.x + t.x, _dragStart.y + t.y);

    CGRect sb = self.superview.bounds;
    CGFloat hw = self.bounds.size.width * 0.5f;
    CGFloat hh = self.bounds.size.height * 0.5f;
    c.x = MAX(hw + 4, MIN(sb.size.width - hw - 4, c.x));
    c.y = MAX(hh + 4, MIN(sb.size.height - hh - 4, c.y));
    self.center = c;
}

@end

// ---------------------------------------------------------------- overlay

// camada cheia presa na propria view do jogo. janela separada depende de cena,
// de keyWindow e de ordem de criacao - tres coisas que o Unity mexe. subview da
// view do jogo aparece sempre, inclusive no meio da partida.
@interface FFOverlayView : UIView
@end

@implementation FFOverlayView

// so o painel recebe toque; o resto atravessa pro jogo
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *v = [super hitTest:point withEvent:event];
    if (v == self) return nil;
    return v;
}

@end

// ---------------------------------------------------------------- estado

static FFOverlayView *g_container = nil;
static FFPanelView *g_panel = nil;
static FFEspView *g_esp = nil;
static BOOL g_visible = YES;

bool ff_panel_visible(void) { return g_visible; }

void ff_panel_toggle(void) {
    if (!g_panel) return;
    g_visible = !g_visible;
    if (g_visible) g_panel.hidden = NO;
    [UIView animateWithDuration:0.16 animations:^{
        g_panel.alpha = g_visible ? 1.0 : 0.0;
        g_panel.transform = g_visible ? CGAffineTransformIdentity
                                      : CGAffineTransformMakeScale(0.86, 0.86);
    } completion:^(BOOL finished) {
        if (!g_visible) g_panel.hidden = YES;
    }];
}

// ---------------------------------------------------------------- gesto 3 dedos x3

static NSTimeInterval g_tapStart = 0;
static NSTimeInterval g_lastTap = 0;
static int   g_tapFingers = 0;
static int   g_tapCount = 0;
static CGPoint g_tapOrigin;
static float g_tapMove = 0;

static void gestureFeed(UIEvent *ev) {
    if (!ev || ev.type != UIEventTypeTouches) return;
    NSSet *all = ev.allTouches;
    if (!all || all.count == 0) return;

    int active = 0, began = 0;
    for (UITouch *t in all) {
        UITouchPhase ph = t.phase;
        if (ph == UITouchPhaseEnded || ph == UITouchPhaseCancelled) continue;
        active++;
        if (ph == UITouchPhaseBegan) {
            began++;
            CGPoint p = [t locationInView:nil];
            if (active == 1) { g_tapOrigin = p; g_tapMove = 0; }
            float dx = (float)(p.x - g_tapOrigin.x);
            float dy = (float)(p.y - g_tapOrigin.y);
            float m = sqrtf(dx * dx + dy * dy);
            if (m > g_tapMove) g_tapMove = m;
        }
    }

    if (began > 0 && g_tapFingers == 0) g_tapStart = CACurrentMediaTime();
    if (active > g_tapFingers) g_tapFingers = active;

    if (active == 0 && g_tapFingers > 0) {
        NSTimeInterval now = CACurrentMediaTime();
        NSTimeInterval dur = now - g_tapStart;

        if (g_tapFingers == 3 && dur < 0.60 && g_tapMove < 45.0f) {
            if (now - g_lastTap < 0.55) g_tapCount++; else g_tapCount = 1;
            g_lastTap = now;
            if (g_tapCount >= 3) {
                g_tapCount = 0;
                ff_panel_toggle();
            }
        } else {
            g_tapCount = 0;
        }
        g_tapFingers = 0;
    }
}

// UIApplication e o unico ponto que ve TODO toque antes do hit-test das janelas.
// hookar UIWindow nao serve: toque que atravessa a overlay (hitTest nil) nunca
// chega no sendEvent da nossa janela.
static void (*orig_sendEvent)(id, SEL, UIEvent *) = nullptr;

static void hook_sendEvent(id self, SEL _cmd, UIEvent *ev) {
    orig_sendEvent(self, _cmd, ev);
    gestureFeed(ev);
}

// ---------------------------------------------------------------- instalacao

// janela principal do jogo: cena ativa primeiro, caminho antigo depois.
static UIWindow *ffKeyWindow(void) {
    UIApplication *app = [UIApplication sharedApplication];

    if (@available(iOS 13.0, *)) {
        UIWindowScene *scene = nil;
        for (UIScene *s in app.connectedScenes) {
            if (![s isKindOfClass:[UIWindowScene class]]) continue;
            if (s.activationState == UISceneActivationStateForegroundActive) {
                scene = (UIWindowScene *)s;
                break;
            }
            if (!scene) scene = (UIWindowScene *)s;
        }
        if (scene) {
            for (UIWindow *w in scene.windows) if (w.isKeyWindow) return w;
            for (UIWindow *w in scene.windows)
                if (w.windowLevel == UIWindowLevelNormal) return w;
        }
    }

    SEL kw = NSSelectorFromString(@"keyWindow");
    if ([app respondsToSelector:kw]) {
        IMP f = [app methodForSelector:kw];
        if (f) {
            id w = ((id (*)(id, SEL))f)(app, kw);
            if (w) return w;
        }
    }
    for (UIWindow *w in app.windows)
        if (w.windowLevel == UIWindowLevelNormal) return w;
    return nil;
}

// monta uma vez, prende na view do jogo e traz pra frente. chamado de novo a
// cada 0,5 s enquanto a camada estiver fora da hierarquia - o Unity troca de
// view em cena, loading e volta de segundo plano.
static void ffAttach(void) {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ ffAttach(); });
        return;
    }

    UIWindow *key = ffKeyWindow();
    if (!key) return;
    UIView *host = key.rootViewController.view ?: key;
    if (!host) return;

    @try {
        if (!g_container) {
            g_container = [[FFOverlayView alloc] initWithFrame:host.bounds];
            g_container.backgroundColor = [UIColor clearColor];
            g_container.multipleTouchEnabled = YES;
            g_container.autoresizingMask = UIViewAutoresizingFlexibleWidth |
                                           UIViewAutoresizingFlexibleHeight;

            g_esp = [[FFEspView alloc] initWithFrame:g_container.bounds];
            g_esp.autoresizingMask = UIViewAutoresizingFlexibleWidth |
                                     UIViewAutoresizingFlexibleHeight;
            [g_container addSubview:g_esp];

            g_panel = [[FFPanelView alloc] initWithFrame:CGRectMake(0, 0, PANEL_W, 10)];
            CGFloat ph = [g_panel fullHeight];
            g_panel.frame = CGRectMake(host.bounds.size.width - PANEL_W - 12, 90, PANEL_W, ph);
            [g_container addSubview:g_panel];
        }

        if (g_container.superview != host) {
            g_container.frame = host.bounds;
            [host addSubview:g_container];
            g_panel.frame = CGRectMake(host.bounds.size.width - PANEL_W - 12, 90,
                                       PANEL_W, [g_panel fullHeight]);
            NSLog(@"[ffaim] painel preso em %.0fx%.0f", host.bounds.size.width,
                  host.bounds.size.height);
        } else {
            [host bringSubviewToFront:g_container];
        }
    } @catch (NSException *e) {
        NSLog(@"[ffaim] overlay falhou: %@", e.reason);
        g_container = nil;
        g_panel = nil;
        g_esp = nil;
    }
}

__attribute__((constructor))
static void ffpanel_init(void) {
    ff_hook_method([UIApplication class], @selector(sendEvent:),
                   (IMP)hook_sendEvent, (IMP *)&orig_sendEvent);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        ffAttach();
        // um timer so: reprende a camada se ela cair e atualiza a linha de status.
        NSTimer *t = [NSTimer timerWithTimeInterval:0.5 repeats:YES block:^(NSTimer *tm) {
            if (!g_container || !g_container.window) ffAttach();
            [g_panel refreshStatus];
        }];
        [[NSRunLoop mainRunLoop] addTimer:t forMode:NSRunLoopCommonModes];
    });
}
