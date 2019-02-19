<?php

declare(strict_types=1);

/**
 * Hoa
 *
 *
 * @license
 *
 * New BSD License
 *
 * Copyright © 2007-2017, Hoa community. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Hoa nor the names of its contributors may be
 *       used to endorse or promote products derived from this software without
 *       specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS AND CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace Hoa\Acl\Test\Unit;

use Hoa\Acl as LUT;
use Hoa\Acl\User as SUT;
use Hoa\Test;

/**
 * Class \Hoa\Acl\Test\Unit\User.
 *
 * Test suite of the user class.
 */
class User extends Test\Unit\Suite
{
    public function case_constructor()
    {
        $this
            ->given(
                $id    = 'foo',
                $label = 'bar'
            )
            ->when($result = new SUT($id, $label))
            ->then
                ->string($result->getId())
                    ->isEqualTo($id)
                ->string($result->getLabel())
                    ->isEqualTo($label);
    }

    public function case_constructor_with_default_label()
    {
        $this
            ->given($id = 'foo')
            ->when($result = new SUT($id))
            ->then
                ->string($result->getId())
                    ->isEqualTo($id)
                ->variable($result->getLabel())
                    ->isNull();
    }

    public function case_add_services()
    {
        $this
            ->given(
                $services = [
                    new LUT\Service('s1'),
                    new LUT\Service('s2'),
                    new LUT\Service('s3')
                ],
                $user     = new SUT('foo'),
                $oldCount = count($this->invoke($user)->getServices())
            )
            ->when($result = $user->addServices($services))
            ->then
                ->object($result)
                    ->isIdenticalTo($user)
                ->integer(count($this->invoke($result)->getServices()))
                    ->isEqualTo($oldCount + count($services))
                ->boolean($result->serviceExists('s1'))
                    ->isTrue()
                ->boolean($result->serviceExists('s2'))
                    ->isTrue()
                ->boolean($result->serviceExists('s3'))
                    ->isTrue()
                ->object($this->invoke($result)->getService('s1'))
                    ->isIdenticalTo($services[0])
                ->object($this->invoke($result)->getService('s2'))
                    ->isIdenticalTo($services[1])
                ->object($this->invoke($result)->getService('s3'))
                    ->isIdenticalTo($services[2]);
    }

    public function case_add_services_not_a_valid_object()
    {
        $this
            ->given($user = new SUT('foo'))
            ->exception(function () use ($user) {
                $user->addServices([null]);
            })
                ->isInstanceOf(LUT\Exception::class);
    }

    public function case_delete_services()
    {
        $this
            ->given(
                $services = [
                    new LUT\Service('s1'),
                    new LUT\Service('s2'),
                    new LUT\Service('s3')
                ],
                $user = new SUT('foo'),
                $user->addServices($services),
                $oldCount = count($this->invoke($user)->getServices()),

                $servicesToDelete = [
                    $services[0],
                    $services[2]
                ]
            )
            ->when($result = $user->deleteServices($servicesToDelete))
            ->then
                ->object($result)
                    ->isIdenticalTo($user)
                ->integer(count($this->invoke($result)->getServices()))
                    ->isEqualTo($oldCount - count($servicesToDelete))
                ->boolean($result->serviceExists('s1'))
                    ->isFalse()
                ->boolean($result->serviceExists('s2'))
                    ->isTrue()
                ->boolean($result->serviceExists('s3'))
                    ->isFalse()
                ->object($this->invoke($result)->getService('s2'))
                    ->isIdenticalTo($services[1]);
    }

    public function case_service_exists()
    {
        $this
            ->given(
                $user = new SUT('foo'),
                $user->addServices([new LUT\Service('s1')])
            )
            ->when($result = $user->serviceExists('s1'))
            ->then
                ->boolean($result)
                    ->isTrue();
    }

    public function case_service_does_not_exist()
    {
        $this
            ->given($user = new SUT('foo'))
            ->when($result = $user->serviceExists('s1'))
            ->then
                ->boolean($result)
                    ->isFalse();
    }

    public function case_get_service()
    {
        $this
            ->given(
                $user    = new SUT('foo'),
                $service = new LUT\Service('s1'),
                $user->addServices([$service])
            )
            ->when($result = $this->invoke($user)->getService('s1'))
            ->then
                ->object($result)
                    ->isIdenticalTo($service);
    }

    public function case_get_undefined_service()
    {
        $this
            ->given($user = new SUT('foo'))
            ->exception(function () use ($user) {
                $this->invoke($user)->getService('s1');
            })
                ->isInstanceOf(LUT\Exception::class);
    }

    public function case_get_services()
    {
        $this
            ->given(
                $services = [
                    new LUT\Service('s1'),
                    new LUT\Service('s2'),
                    new LUT\Service('s3')
                ],
                $user = new SUT('foo'),
                $user->addServices($services)
            )
            ->when($result = $this->invoke($user)->getServices())
            ->then
                ->array($result)
                    ->isEqualTo([
                        's1' => $services[0],
                        's2' => $services[1],
                        's3' => $services[2]
                    ]);
    }

    public function case_set_id()
    {
        $this
            ->given(
                $oldId = 'foo',
                $user  = new SUT($oldId),
                $id    = 'bar'
            )
            ->when($result = $this->invoke($user)->setId($id))
            ->then
                ->string($result)
                    ->isEqualTo($oldId)
                ->string($user->getId())
                    ->isEqualTo($id);
    }

    public function case_set_label()
    {
        $this
            ->given(
                $id       = 'foo',
                $oldLabel = 'bar',
                $user     = new SUT($id, $oldLabel),
                $label    = 'baz'
            )
            ->when($result = $user->setLabel($label))
            ->then
                ->string($result)
                    ->isEqualTo($oldLabel)
                ->string($user->getLabel())
                    ->isEqualTo($label);
    }
}
