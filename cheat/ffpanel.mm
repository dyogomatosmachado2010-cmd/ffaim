// ffpanel.mm - painel flutuante (UIKit), overlay de ESP e gesto de 3 dedos x3.
// tudo na main thread; o core publica o snapshot do ESP por lock (ffaim.mm).
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/runtime.h>
#import <math.h>
#import "ffaim.h"
#include "ffhook.h"

#define PANEL_W 268.0f
#define HEADER_H 38.0f

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

        UIColor *col = [UIColor colorWithRed:0.35 green:1.0 blue:0.45 alpha:0.95];

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
            CGContextSetStrokeColorWithColor(ctx, [UIColor colorWithWhite:1.0 alpha:0.35].CGColor);
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
@end

@implementation FFPanelView {
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
    UISegmentedControl *_boneSeg;
}

- (UILabel *)label:(NSString *)t frame:(CGRect)f {
    UILabel *l = [[UILabel alloc] initWithFrame:f];
    l.text = t;
    l.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    l.textColor = [UIColor colorWithWhite:0.93 alpha:1.0];
    l.backgroundColor = [UIColor clearColor];
    return l;
}

- (UILabel *)valueLabel:(CGRect)f {
    UILabel *l = [[UILabel alloc] initWithFrame:f];
    l.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightBold];
    l.textColor = [UIColor colorWithRed:0.45 green:0.85 blue:1.0 alpha:1.0];
    l.textAlignment = NSTextAlignmentRight;
    l.backgroundColor = [UIColor clearColor];
    return l;
}

- (instancetype)initWithFrame:(CGRect)frame {
    if ((self = [super initWithFrame:frame])) {
        self.backgroundColor = [UIColor clearColor];
        self.layer.cornerRadius = 16;
        self.layer.masksToBounds = YES;
        self.layer.borderWidth = 1.0;
        self.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.12].CGColor;

        UIBlurEffect *eff = [UIBlurEffect effectWithStyle:UIBlurEffectStyleDark];
        UIVisualEffectView *blur = [[UIVisualEffectView alloc] initWithEffect:eff];
        blur.frame = self.bounds;
        blur.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        [self addSubview:blur];

        [self buildHeader];
        [self buildBody];

        self.frame = CGRectMake(frame.origin.x, frame.origin.y, PANEL_W, _fullH);
    }
    return self;
}

- (CGFloat)fullHeight { return _fullH; }

- (void)buildHeader {
    UIView *h = [[UIView alloc] initWithFrame:CGRectMake(0, 0, PANEL_W, HEADER_H)];
    h.backgroundColor = [UIColor colorWithWhite:1.0 alpha:0.05];
    [self addSubview:h];

    UILabel *t = [self label:@"FF 1.28" frame:CGRectMake(14, 0, 120, HEADER_H)];
    t.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightBold];
    t.textColor = [UIColor colorWithRed:0.45 green:0.85 blue:1.0 alpha:1.0];
    [h addSubview:t];

    UIButton *min = [UIButton buttonWithType:UIButtonTypeSystem];
    min.frame = CGRectMake(PANEL_W - 40, 4, 30, 30);
    [min setTitle:@"–" forState:UIControlStateNormal];
    min.titleLabel.font = [UIFont systemFontOfSize:22 weight:UIFontWeightBold];
    [min setTitleColor:[UIColor colorWithWhite:0.85 alpha:1.0] forState:UIControlStateNormal];
    [min addTarget:self action:@selector(onMinimize) forControlEvents:UIControlEventTouchUpInside];
    [h addSubview:min];

    UIPanGestureRecognizer *pan =
        [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(onPan:)];
    [h addGestureRecognizer:pan];
}

- (void)buildBody {
    CGFloat y = 6;
    _body = [[UIView alloc] initWithFrame:CGRectMake(0, HEADER_H, PANEL_W, 10)];
    [self addSubview:_body];

    // aimbot
    [_body addSubview:[self label:@"Aimbot" frame:CGRectMake(14, y, 160, 30)]];
    _aimSw = [[UISwitch alloc] initWithFrame:CGRectMake(PANEL_W - 14 - 51, y + 1, 51, 31)];
    _aimSw.transform = CGAffineTransformMakeScale(0.78, 0.78);
    _aimSw.on = g_cfg.aimbot;
    [_aimSw addTarget:self action:@selector(onSwitch) forControlEvents:UIControlEventValueChanged];
    [_body addSubview:_aimSw];
    y += 34;

    // esp
    [_body addSubview:[self label:@"ESP" frame:CGRectMake(14, y, 160, 30)]];
    _espSw = [[UISwitch alloc] initWithFrame:CGRectMake(PANEL_W - 14 - 51, y + 1, 51, 31)];
    _espSw.transform = CGAffineTransformMakeScale(0.78, 0.78);
    _espSw.on = g_cfg.esp;
    [_espSw addTarget:self action:@selector(onSwitch) forControlEvents:UIControlEventValueChanged];
    [_body addSubview:_espSw];
    y += 36;

    // fov
    [_body addSubview:[self label:@"FOV" frame:CGRectMake(14, y, 80, 18)]];
    _fovVal = [self valueLabel:CGRectMake(PANEL_W - 70, y, 56, 18)];
    _fovVal.text = [NSString stringWithFormat:@"%.0f°", g_cfg.fov];
    [_body addSubview:_fovVal];
    y += 20;
    _fovSl = [[UISlider alloc] initWithFrame:CGRectMake(14, y, PANEL_W - 28, 26)];
    _fovSl.minimumValue = 5; _fovSl.maximumValue = 180;
    _fovSl.value = g_cfg.fov;
    [_fovSl addTarget:self action:@selector(onFov) forControlEvents:UIControlEventValueChanged];
    [_fovSl addTarget:self action:@selector(onCommit) forControlEvents:
        UIControlEventTouchUpInside | UIControlEventTouchUpOutside];
    [_body addSubview:_fovSl];
    y += 34;

    // smooth
    [_body addSubview:[self label:@"Smooth" frame:CGRectMake(14, y, 80, 18)]];
    _smoothVal = [self valueLabel:CGRectMake(PANEL_W - 70, y, 56, 18)];
    _smoothVal.text = [NSString stringWithFormat:@"%.0f%%", g_cfg.smooth * 100];
    [_body addSubview:_smoothVal];
    y += 20;
    _smoothSl = [[UISlider alloc] initWithFrame:CGRectMake(14, y, PANEL_W - 28, 26)];
    _smoothSl.minimumValue = 0; _smoothSl.maximumValue = 1;
    _smoothSl.value = g_cfg.smooth;
    [_smoothSl addTarget:self action:@selector(onSmooth) forControlEvents:UIControlEventValueChanged];
    [_smoothSl addTarget:self action:@selector(onCommit) forControlEvents:
        UIControlEventTouchUpInside | UIControlEventTouchUpOutside];
    [_body addSubview:_smoothSl];
    y += 34;

    // bone
    _boneSeg = [[UISegmentedControl alloc] initWithItems:@[@"Head", @"Neck", @"Chest", @"Hip"]];
    _boneSeg.frame = CGRectMake(14, y, PANEL_W - 28, 28);
    _boneSeg.selectedSegmentIndex = g_cfg.bone;
    _boneSeg.tintColor = [UIColor colorWithRed:0.35 green:0.7 blue:1.0 alpha:1.0];
    [_boneSeg addTarget:self action:@selector(onBone) forControlEvents:UIControlEventValueChanged];
    if (@available(iOS 13.0, *)) {
        _boneSeg.selectedSegmentTintColor = [UIColor colorWithRed:0.2 green:0.5 blue:0.9 alpha:1.0];
    }
    [_body addSubview:_boneSeg];
    y += 36;

    // team
    [_body addSubview:[self label:@"Team check" frame:CGRectMake(14, y, 160, 30)]];
    _teamSw = [[UISwitch alloc] initWithFrame:CGRectMake(PANEL_W - 14 - 51, y + 1, 51, 31)];
    _teamSw.transform = CGAffineTransformMakeScale(0.78, 0.78);
    _teamSw.on = g_cfg.teamCheck;
    [_teamSw addTarget:self action:@selector(onSwitch) forControlEvents:UIControlEventValueChanged];
    [_body addSubview:_teamSw];
    y += 34;

    UILabel *hint = [self label:@"3 dedos x3 = painel" frame:CGRectMake(14, y, PANEL_W - 28, 16)];
    hint.font = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightRegular];
    hint.textColor = [UIColor colorWithWhite:0.6 alpha:1.0];
    [_body addSubview:hint];
    y += 18;

    _body.frame = CGRectMake(0, HEADER_H, PANEL_W, y);
    _fullH = HEADER_H + y;
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

// ---------------------------------------------------------------- window

@interface FFOverlayWindow : UIWindow
@end

@implementation FFOverlayWindow

// so o painel recebe toque; o resto passa pro jogo
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *v = [super hitTest:point withEvent:event];
    if (v == self || v == self.rootViewController.view) return nil;
    return v;
}

@end

// ---------------------------------------------------------------- estado

static FFOverlayWindow *g_win = nil;
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

static void ffInstallUI(int attempt);

static void ffInstallUI(int attempt) {
    if (g_win) return;

    UIWindow *key = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if (![s isKindOfClass:[UIWindowScene class]]) continue;
            for (UIWindow *w in ((UIWindowScene *)s).windows) {
                if (w.isKeyWindow) { key = w; break; }
            }
            if (key) break;
        }
    }
    if (!key) key = [UIApplication sharedApplication].keyWindow;

    if (!key) {
        if (attempt < 80) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ ffInstallUI(attempt + 1); });
        }
        return;
    }

    CGRect sb = [UIScreen mainScreen].bounds;

    g_win = [[FFOverlayWindow alloc] initWithFrame:sb];
    if (@available(iOS 13.0, *)) g_win.windowScene = key.windowScene;
    g_win.windowLevel = UIWindowLevelAlert + 100;
    g_win.backgroundColor = [UIColor clearColor];
    g_win.multipleTouchEnabled = YES;

    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor clearColor];
    vc.view.multipleTouchEnabled = YES;
    g_win.rootViewController = vc;
    [g_win setHidden:NO];

    g_esp = [[FFEspView alloc] initWithFrame:sb];
    [vc.view addSubview:g_esp];

    g_panel = [[FFPanelView alloc] initWithFrame:CGRectMake(0, 0, PANEL_W, 10)];
    CGFloat ph = [g_panel fullHeight];
    g_panel.frame = CGRectMake(sb.size.width - PANEL_W - 12, 90, PANEL_W, ph);
    [vc.view addSubview:g_panel];

    NSLog(@"[ffaim] painel instalado em %.0fx%.0f", sb.size.width, sb.size.height);
}

__attribute__((constructor))
static void ffpanel_init(void) {
    ff_hook_method([UIApplication class], @selector(sendEvent:),
                   (IMP)hook_sendEvent, (IMP *)&orig_sendEvent);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ ffInstallUI(0); });
}
